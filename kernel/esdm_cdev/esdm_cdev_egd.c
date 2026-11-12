// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * ESDM character device frontend - EGD client
 *
 * The module reaches the ESDM over its EGD socket, a Unix domain stream socket
 * of the esdm-server in user space, with the ESDM's extensions of the EGD
 * protocol. No protobuf, no RPC: every request is a command byte with fixed
 * size arguments, every answer has a size known from the request or announced
 * by a length prefix.
 *
 * Connecting
 * ----------
 * The path of a Unix domain socket is looked up in the file system context of
 * the task calling connect(): its root, its mount namespace. Connecting in the
 * context of the process reading a device would let a process in a container
 * have the module talk to whatever the container has at that path - with the
 * module's privileges towards it, see below. So connections are made on the
 * module's workqueue only. Its workers are kernel threads, forked by kthreadd
 * with CLONE_FS: they share the fs_struct of init, i.e. its root and working
 * directory in the initial mount namespace, also after the initramfs handed
 * over to the real root, and they run with the initial credentials. Since
 * Linux 7.3 kernel threads no longer share init's fs_struct: theirs has an
 * empty root (nullfs), where every lookup fails with -ENOENT, and a kernel
 * thread takes the one of init for a lookup with scoped_with_init_fs(),
 * which the work below does around everything it runs.
 *
 * That makes the module's connections root's: the ESDM takes the peer
 * credentials at connect time, and honours the entropy claims and the
 * privileged commands of a root peer. The module therefore checks its own
 * callers before it sends any of those, see esdm_cdev_main.c.
 *
 * Once connected, the requests are carried out in the context of the caller:
 * sending and receiving on a connected socket involves no path lookup, and the
 * caller's signals interrupt the waits - except the one for the answer of a
 * command that changes something in the ESDM, see esdm_cdev_recv_committed().
 *
 * Connections
 * -----------
 * ESDM_CDEV_CONNS connections, each serving one request at a time - EGD has
 * no request identifiers, so answers are matched to requests by their order.
 * A request takes a connection that is free, or waits for one, as long as a
 * transfer at most. A request holds its connection for the ESDM's answers
 * only: it brings what it sends along, rather than reading user memory then.
 * A connection that failed in any way is closed, as the position of the
 * stream is unknown then, and made anew by the next request on it. After a
 * failure of the ESDM - no connection, a timeout, an answer that does not fit
 * - no connection is made for a while, growing up to ESDM_CDEV_BACKOFF_MAX_MS
 * until a request succeeds, so that a missing or frozen ESDM costs a failed
 * connect or a timeout now and then rather than one per read.
 *
 * Every answer is untrusted input: its lengths are checked against what was
 * asked for and against the protocol's bounds before anything is read, and a
 * connection with an answer that does not fit is closed.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/completion.h>
#include <linux/err.h>
#include <linux/fs_struct.h>
#include <linux/jiffies.h>
#include <linux/minmax.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/mutex.h>
#include <linux/net.h>
#include <linux/refcount.h>
#include <linux/sched/signal.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/un.h>
#include <linux/version.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <net/net_namespace.h>
#include <net/sock.h>

/* Moved from asm/ in Linux 6.12 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif

#include "esdm_cdev.h"

static char *egd_socket = "/run/esdm-egd.socket";
module_param(egd_socket, charp, 0444);
MODULE_PARM_DESC(egd_socket,
		 "Path of the ESDM's EGD socket (default: /run/esdm-egd.socket)");

static unsigned int timeout_ms = 5000;
module_param(timeout_ms, uint, 0644);
MODULE_PARM_DESC(timeout_ms,
		 "Bound in milliseconds on connecting and on each transfer (100 to 60000, default: 5000)");

#define ESDM_CDEV_CONNS 4
#define ESDM_CDEV_BACKOFF_MIN_MS 50
#define ESDM_CDEV_BACKOFF_MAX_MS 2000

struct esdm_cdev_conn {
	/* Serializes the requests, and guards the socket */
	struct mutex lock;
	/* NULL while not connected */
	struct socket *sock;
};

static struct esdm_cdev_conn esdm_cdev_conns[ESDM_CDEV_CONNS];
static atomic_t esdm_cdev_conn_next = ATOMIC_INIT(0);
/* Requests waiting for a connection to be freed */
static DECLARE_WAIT_QUEUE_HEAD(esdm_cdev_conn_wait);
struct workqueue_struct *esdm_cdev_wq;

/* No connect before esdm_cdev_retry_at while esdm_cdev_backoff_ms is set */
static DEFINE_SPINLOCK(esdm_cdev_backoff_lock);
static unsigned long esdm_cdev_retry_at;
static unsigned int esdm_cdev_backoff_ms;

/* Whether the last connect succeeded, -1 before the first: for the log only */
static atomic_t esdm_cdev_reachable = ATOMIC_INIT(-1);

static unsigned int esdm_cdev_timeout_ms(void)
{
	return clamp_t(unsigned int, READ_ONCE(timeout_ms), 100, 60000);
}

/* A status of the ESDM: success, or a negative errno - nothing else */
static int esdm_cdev_status(const u8 *val, int *status)
{
	s32 s = (s32)get_unaligned_be32(val);

	if (s > 0 || s < -MAX_ERRNO)
		return -EPROTO;
	*status = s;

	return 0;
}

/******************************** Connections ********************************/

/*
 * After a failure of the ESDM (@failed), no connect for a while, longer each
 * time; after a request it answered, connects again at once.
 */
static void esdm_cdev_backoff(bool failed)
{
	spin_lock(&esdm_cdev_backoff_lock);
	if (failed) {
		esdm_cdev_backoff_ms = clamp(esdm_cdev_backoff_ms * 2,
					     ESDM_CDEV_BACKOFF_MIN_MS,
					     ESDM_CDEV_BACKOFF_MAX_MS);
		esdm_cdev_retry_at =
			jiffies + msecs_to_jiffies(esdm_cdev_backoff_ms);
	} else {
		esdm_cdev_backoff_ms = 0;
	}
	spin_unlock(&esdm_cdev_backoff_lock);
}

static bool esdm_cdev_backing_off(void)
{
	bool ret;

	spin_lock(&esdm_cdev_backoff_lock);
	ret = esdm_cdev_backoff_ms &&
	      time_before(jiffies, esdm_cdev_retry_at);
	spin_unlock(&esdm_cdev_backoff_lock);

	return ret;
}

/* A connect on the workqueue, see "Connecting" above */
struct esdm_cdev_connect {
	struct work_struct work;
	struct completion done;
	/* The waiter's and the work's */
	refcount_t ref;
	int ret;
	/* The connection, until the waiter takes it */
	struct socket *sock;
};

static void esdm_cdev_connect_put(struct esdm_cdev_connect *c)
{
	if (!refcount_dec_and_test(&c->ref))
		return;

	/* Made for a waiter that gave up */
	if (c->sock)
		sock_release(c->sock);
	kfree(c);
}

static int esdm_cdev_connect_init(struct socket **res)
{
	/*
	 * In a struct sockaddr_storage, as the system calls pass addresses:
	 * unix_mkname_bsd() terminates the path at sun_path[108], past the
	 * end of a struct sockaddr_un. Kernels without "net: avoid address
	 * overwrite in kernel_connect", such as early 6.1 ones, do that on the
	 * caller's address.
	 */
	struct sockaddr_storage addr = { .ss_family = AF_UNIX };
	struct sockaddr_un *sun = (struct sockaddr_un *)&addr;
	struct socket *sock;
	int ret;

	strscpy(sun->sun_path, egd_socket, sizeof(sun->sun_path));

	ret = sock_create_kern(&init_net, AF_UNIX, SOCK_STREAM, 0, &sock);
	if (ret)
		return ret;

	/*
	 * Non-blocking: a full listen backlog of the ESDM is a failure to
	 * connect rather than a wait. The address type of kernel_connect()
	 * differs between kernel versions, the void pointer fits both.
	 */
	ret = kernel_connect(sock, (void *)&addr, sizeof(*sun), O_NONBLOCK);
	if (ret) {
		sock_release(sock);
		return ret;
	}

	*res = sock;

	return 0;
}

static void esdm_cdev_connect_work(struct work_struct *work)
{
	struct esdm_cdev_connect *c =
		container_of(work, struct esdm_cdev_connect, work);

	/* The file system context of init, see "Connecting" above */
#ifdef scoped_with_init_fs
	scoped_with_init_fs()
		c->ret = esdm_cdev_connect_init(&c->sock);
#else
	c->ret = esdm_cdev_connect_init(&c->sock);
#endif
	complete(&c->done);
	esdm_cdev_connect_put(c);
}

/* Caller holds conn->lock */
static int esdm_cdev_conn_connect(struct esdm_cdev_conn *conn)
{
	struct esdm_cdev_connect *c;
	long left;
	int ret;

	if (conn->sock)
		return 0;

	if (esdm_cdev_backing_off())
		return -ENOTCONN;

	c = kzalloc(sizeof(*c), GFP_KERNEL);
	if (!c)
		return -ENOMEM;

	INIT_WORK(&c->work, esdm_cdev_connect_work);
	init_completion(&c->done);
	refcount_set(&c->ref, 2);
	queue_work(esdm_cdev_wq, &c->work);

	left = wait_for_completion_interruptible_timeout(
		&c->done, msecs_to_jiffies(esdm_cdev_timeout_ms()));
	if (left > 0) {
		ret = c->ret;
		conn->sock = c->sock;
		c->sock = NULL;
	} else {
		ret = left ? (int)left : -ETIMEDOUT;
	}
	esdm_cdev_connect_put(c);

	if (ret == -ERESTARTSYS)
		return ret;
	if (ret) {
		esdm_cdev_backoff(true);
		if (atomic_xchg(&esdm_cdev_reachable, 0) != 0)
			pr_warn("cannot connect to the ESDM at %s: %d\n",
				egd_socket, ret);
		return -ENOTCONN;
	}

	/*
	 * The backoff stays until a request succeeded: an ESDM that accepts
	 * connections but does not answer would otherwise be waited for the
	 * full timeout on every request.
	 */
	if (atomic_xchg(&esdm_cdev_reachable, 1) != 1)
		pr_info("connected to the ESDM at %s\n", egd_socket);

	return 0;
}

/*
 * Close the connection of a failed request. @backoff: the failure was the
 * ESDM's - an answer that does not fit, a timeout, a closed connection. A
 * caller that was interrupted is no reason to make anybody else wait.
 */
static void esdm_cdev_conn_drop(struct esdm_cdev_conn *conn, bool backoff)
{
	sock_release(conn->sock);
	conn->sock = NULL;

	if (backoff)
		esdm_cdev_backoff(true);
}

/* A free connection, locked, looking from the one at @start on */
static struct esdm_cdev_conn *esdm_cdev_conn_try(unsigned int start)
{
	unsigned int i;

	for (i = 0; i < ESDM_CDEV_CONNS; i++) {
		struct esdm_cdev_conn *conn =
			&esdm_cdev_conns[(start + i) % ESDM_CDEV_CONNS];

		if (mutex_trylock(&conn->lock))
			return conn;
	}

	return NULL;
}

/*
 * A free connection, or the first one freed within the timeout. A request
 * that gets none fails as one the ESDM did not answer: the connections are
 * all busy with requests the ESDM takes its time for.
 */
static struct esdm_cdev_conn *esdm_cdev_conn_get(void)
{
	struct esdm_cdev_conn *conn = NULL;
	unsigned int start;
	long left;

	start = (unsigned int)atomic_inc_return(&esdm_cdev_conn_next);
	left = wait_event_interruptible_timeout(
		esdm_cdev_conn_wait, (conn = esdm_cdev_conn_try(start)) != NULL,
		msecs_to_jiffies(esdm_cdev_timeout_ms()));
	if (left < 0)
		return ERR_PTR(-ERESTARTSYS);
	if (!conn)
		return ERR_PTR(-ETIMEDOUT);

	return conn;
}

static void esdm_cdev_conn_put(struct esdm_cdev_conn *conn)
{
	mutex_unlock(&conn->lock);
	wake_up(&esdm_cdev_conn_wait);
}

/********************************* Transfers *********************************/

/* One transfer on a connection: a request and its answer */
struct esdm_cdev_xfer {
	struct socket *sock;
	/* Whether any of the request went out */
	bool sent;
};

/* Send all of @buf */
static int esdm_cdev_send(struct esdm_cdev_xfer *x, const void *buf,
			  size_t len)
{
	while (len) {
		struct kvec iov = { .iov_base = (void *)buf, .iov_len = len };
		/* A peer that went away is an error, not a SIGPIPE */
		struct msghdr msg = { .msg_flags = MSG_NOSIGNAL };
		int ret = kernel_sendmsg(x->sock, &msg, &iov, 1, len);

		if (ret == -EAGAIN)
			return -ETIMEDOUT;
		if (ret < 0)
			return ret;
		if (!ret || (size_t)ret > len)
			return -EIO;

		x->sent = true;
		buf += ret;
		len -= (size_t)ret;
	}

	return 0;
}

/* Receive exactly @len bytes */
static int esdm_cdev_recv(struct esdm_cdev_xfer *x, void *buf, size_t len)
{
	while (len) {
		struct kvec iov = { .iov_base = buf, .iov_len = len };
		struct msghdr msg = { .msg_flags = 0 };
		int ret = kernel_recvmsg(x->sock, &msg, &iov, 1, len,
					 MSG_WAITALL);

		/* The ESDM closed the connection */
		if (!ret)
			return -ECONNRESET;
		if (ret == -EAGAIN)
			return -ETIMEDOUT;
		if (ret < 0)
			return ret;
		if ((size_t)ret > len)
			return -EIO;

		buf += ret;
		len -= (size_t)ret;
	}

	return 0;
}

static bool esdm_cdev_interrupted(int ret)
{
	return ret == -ERESTARTSYS || ret == -EINTR || ret == -ERESTARTNOINTR ||
	       ret == -ERESTARTNOHAND || ret == -ERESTART_RESTARTBLOCK;
}

/*
 * Receive exactly @len bytes of the answer to a command the ESDM carries out
 * once it has it, also when nobody waits for the answer any more - the
 * commands changing its entropy accounting or its DRNGs. A caller interrupted
 * now would have the command restarted, and carried out twice. So the answer
 * is waited for despite signals, bounded by the timeout as every wait; only a
 * fatal signal ends the wait, after which nothing is restarted. The socket's
 * waits end at any signal, so with one pending, the answer is polled for.
 */
static int esdm_cdev_recv_committed(struct esdm_cdev_xfer *x, void *buf,
				    size_t len)
{
	unsigned long end = jiffies + READ_ONCE(x->sock->sk->sk_rcvtimeo);

	while (len) {
		struct kvec iov = { .iov_base = buf, .iov_len = len };
		struct msghdr msg = { .msg_flags = 0 };
		bool polling = signal_pending(current);
		int ret;

		if (fatal_signal_pending(current))
			return -EINTR;

		ret = kernel_recvmsg(x->sock, &msg, &iov, 1, len,
				     polling ? MSG_DONTWAIT : MSG_WAITALL);

		if (!ret)
			return -ECONNRESET;
		if (polling && ret == -EAGAIN) {
			if (time_after(jiffies, end))
				return -ETIMEDOUT;
			schedule_timeout_uninterruptible(1);
			continue;
		}
		/* A signal came while waiting */
		if (esdm_cdev_interrupted(ret))
			continue;
		if (ret == -EAGAIN)
			return -ETIMEDOUT;
		if (ret < 0)
			return ret;
		if ((size_t)ret > len)
			return -EIO;

		buf += ret;
		len -= (size_t)ret;
	}

	return 0;
}

/*
 * Carry out one request with @op on a connection: connected, with the
 * timeouts set, and locked. One whose connection the ESDM closed - idle, or
 * on its restart - is made once more on a fresh one.
 *
 * @changes: the request changes something in the ESDM, which carries it out
 * once it has it. One that went out is therefore not restarted, nor made
 * again, whatever happens to its answer.
 *
 * Returns 0, -ERESTARTSYS when the caller was interrupted, -ENOTCONN when the
 * ESDM cannot be reached, -ETIMEDOUT when no connection was free in time, or
 * the error of @op.
 */
static int esdm_cdev_invoke(int (*op)(struct esdm_cdev_xfer *x, void *arg),
			    void *arg, bool changes)
{
	struct esdm_cdev_conn *conn = esdm_cdev_conn_get();
	unsigned int attempt;
	int ret = -ENOTCONN;

	if (IS_ERR(conn))
		return PTR_ERR(conn);

	for (attempt = 0; attempt < 2; attempt++) {
		long tmo = msecs_to_jiffies(esdm_cdev_timeout_ms());
		struct esdm_cdev_xfer x = { 0 };
		bool intr, again;

		ret = esdm_cdev_conn_connect(conn);
		if (ret)
			break;

		WRITE_ONCE(conn->sock->sk->sk_rcvtimeo, tmo);
		WRITE_ONCE(conn->sock->sk->sk_sndtimeo, tmo);

		x.sock = conn->sock;
		ret = op(&x, arg);
		if (!ret) {
			esdm_cdev_backoff(false);
			break;
		}

		/* Gone out: its error, or -EINTR for a fatal signal */
		if (changes && x.sent) {
			intr = esdm_cdev_interrupted(ret);
			esdm_cdev_conn_drop(conn, !intr);
			if (intr)
				ret = -EINTR;
			break;
		}

		/* Whatever went wrong, the stream is lost */
		intr = esdm_cdev_interrupted(ret) || signal_pending(current);
		again = !attempt && !intr &&
			(ret == -ECONNRESET || ret == -EPIPE);
		esdm_cdev_conn_drop(conn, !intr && !again);
		if (intr) {
			ret = -ERESTARTSYS;
			break;
		}
		if (!again)
			break;
	}

	esdm_cdev_conn_put(conn);

	return ret;
}

/*********************************** Reads ***********************************/

struct esdm_cdev_read_op {
	u8 read;
	u8 *buf;
	size_t len;
	size_t got;
};

static int esdm_cdev_read_op(struct esdm_cdev_xfer *x, void *arg)
{
	struct esdm_cdev_read_op *op = arg;
	u8 req[6] = { ESDM_EGD_CMD_ESDM_BULK_READ, op->read }, val[4];
	u32 got;
	int ret;

	put_unaligned_be32((u32)op->len, req + 2);

	ret = esdm_cdev_send(x, req, sizeof(req));
	if (!ret)
		ret = esdm_cdev_recv(x, val, sizeof(val));
	if (ret)
		return ret;

	/* More than asked for is not the protocol */
	got = get_unaligned_be32(val);
	if (got > op->len)
		return -EPROTO;

	ret = esdm_cdev_recv(x, op->buf, got);
	if (ret) {
		memzero_explicit(op->buf, got);
		return ret;
	}
	op->got = got;

	return 0;
}

int esdm_cdev_egd_read(u8 read, u8 *buf, size_t len)
{
	struct esdm_cdev_read_op op = {
		.read = read,
		.buf = buf,
		.len = min_t(size_t, len, ESDM_EGD_MAX_BULK),
	};
	int ret;

	if (!len)
		return 0;

	ret = esdm_cdev_invoke(esdm_cdev_read_op, &op, false);

	return ret ? ret : (int)op.got;
}

/********************************** Writes ***********************************/

struct esdm_cdev_insert_op {
	/* The command, its length and the data, @len bytes */
	u8 *req;
	size_t len;
	int status;
};

static int esdm_cdev_insert_op(struct esdm_cdev_xfer *x, void *arg)
{
	struct esdm_cdev_insert_op *op = arg;
	u8 val[4];
	int ret;

	ret = esdm_cdev_send(x, op->req, op->len);
	if (!ret)
		ret = esdm_cdev_recv(x, val, sizeof(val));
	if (!ret)
		ret = esdm_cdev_status(val, &op->status);

	return ret;
}

ssize_t esdm_cdev_egd_insert_user(const char __user *ubuf, size_t len)
{
	struct esdm_cdev_insert_op op = { 0 };
	size_t done = 0, room = 5 + min_t(size_t, len, ESDM_EGD_MAX_BULK);
	int ret = 0;

	if (!len)
		return 0;

	op.req = kvmalloc(room, GFP_KERNEL);
	if (!op.req)
		return -ENOMEM;

	while (done < len) {
		size_t want = min_t(size_t, len - done, ESDM_EGD_MAX_BULK);
		size_t got;

		/*
		 * User memory is copied before a connection is taken: reading
		 * it may take as long as somebody else wants - a page of a
		 * file of a FUSE daemon that does not answer - and the
		 * connection would be held for that long, with every request
		 * of every other caller waiting for it.
		 */
		got = want - copy_from_user(op.req + 5, ubuf + done, want);
		if (!got) {
			ret = -EFAULT;
			break;
		}

		op.req[0] = ESDM_EGD_CMD_ESDM_BULK_INSERT;
		put_unaligned_be32((u32)got, op.req + 1);
		op.len = 5 + got;

		ret = esdm_cdev_invoke(esdm_cdev_insert_op, &op, false);
		if (!ret)
			ret = op.status;
		if (ret)
			break;
		done += got;

		if (got < want) {
			ret = -EFAULT;
			break;
		}

		/* As the kernel's devices: a signal ends the write */
		if (signal_pending(current))
			break;
		cond_resched();
	}

	kvfree_sensitive(op.req, room);

	/* What was written is returned, an error only without any */
	return done ? (ssize_t)done : ret;
}

/******************************** Queries ************************************/

static int esdm_cdev_state_op(struct esdm_cdev_xfer *x, void *arg)
{
	u32 *fields = arg;
	u8 req = ESDM_EGD_CMD_ESDM_GET_STATE, num, val[4];
	unsigned int i;
	int ret;

	ret = esdm_cdev_send(x, &req, sizeof(req));
	if (!ret)
		ret = esdm_cdev_recv(x, &num, sizeof(num));
	if (ret)
		return ret;

	/* Fields are only ever appended, the ones known here are required */
	if (num < ESDM_EGD_STATE_NUM_FIELDS)
		return -EPROTO;

	for (i = 0; i < num; i++) {
		ret = esdm_cdev_recv(x, val, sizeof(val));
		if (ret)
			return ret;
		if (i < ESDM_EGD_STATE_NUM_FIELDS)
			fields[i] = get_unaligned_be32(val);
	}

	return 0;
}

int esdm_cdev_egd_get_state(u32 fields[ESDM_EGD_STATE_NUM_FIELDS])
{
	return esdm_cdev_invoke(esdm_cdev_state_op, fields, false);
}

struct esdm_cdev_status_op {
	bool json;
	char *report;
	size_t len;
};

static int esdm_cdev_status_op(struct esdm_cdev_xfer *x, void *arg)
{
	struct esdm_cdev_status_op *op = arg;
	u8 req = op->json ? ESDM_EGD_CMD_ESDM_STATUS_JSON :
			    ESDM_EGD_CMD_ESDM_STATUS;
	u8 val[4];
	char *report;
	u32 len;
	int ret;

	ret = esdm_cdev_send(x, &req, sizeof(req));
	if (!ret)
		ret = esdm_cdev_recv(x, val, sizeof(val));
	if (ret)
		return ret;

	len = get_unaligned_be32(val);
	if (len > ESDM_EGD_MAX_STATUS)
		return -EPROTO;

	report = kvmalloc(len + 1, GFP_KERNEL);
	if (!report)
		return -ENOMEM;

	ret = esdm_cdev_recv(x, report, len);
	if (ret) {
		kvfree(report);
		return ret;
	}
	report[len] = '\0';

	op->report = report;
	op->len = len;

	return 0;
}

int esdm_cdev_egd_status(bool json, char **report, size_t *len)
{
	struct esdm_cdev_status_op op = { .json = json };
	int ret;

	ret = esdm_cdev_invoke(esdm_cdev_status_op, &op, false);
	if (ret)
		return ret;

	*report = op.report;
	*len = op.len;

	return 0;
}

struct esdm_cdev_priv_op {
	u8 cmd;
	bool has_arg;
	u32 arg;
	int status;
};

static int esdm_cdev_priv_op(struct esdm_cdev_xfer *x, void *arg)
{
	struct esdm_cdev_priv_op *op = arg;
	u8 req[5] = { op->cmd }, val[4];
	int ret;

	put_unaligned_be32(op->arg, req + 1);

	ret = esdm_cdev_send(x, req, op->has_arg ? 5 : 1);
	if (!ret)
		ret = esdm_cdev_recv_committed(x, val, sizeof(val));
	if (!ret)
		ret = esdm_cdev_status(val, &op->status);

	return ret;
}

int esdm_cdev_egd_priv(u8 cmd, bool has_arg, u32 arg)
{
	struct esdm_cdev_priv_op op = {
		.cmd = cmd,
		.has_arg = has_arg,
		.arg = arg,
	};
	int ret;

	ret = esdm_cdev_invoke(esdm_cdev_priv_op, &op, true);

	return ret ? ret : op.status;
}

/****************************** Initialization *******************************/

int esdm_cdev_egd_init(void)
{
	unsigned int i;

	if (!egd_socket || !*egd_socket ||
	    strlen(egd_socket) >= sizeof_field(struct sockaddr_un, sun_path)) {
		pr_err("invalid EGD socket path\n");
		return -EINVAL;
	}

	for (i = 0; i < ESDM_CDEV_CONNS; i++)
		mutex_init(&esdm_cdev_conns[i].lock);

	esdm_cdev_wq = alloc_workqueue("esdm_cdev", WQ_UNBOUND, 0);
	if (!esdm_cdev_wq)
		return -ENOMEM;

	return 0;
}

/*
 * Only once nobody uses the module any more: the devices and proc files are
 * gone, and with them every caller of the functions above.
 */
void esdm_cdev_egd_fini(void)
{
	unsigned int i;

	/* Waits for the connects still running, whose waiters gave up */
	destroy_workqueue(esdm_cdev_wq);

	for (i = 0; i < ESDM_CDEV_CONNS; i++) {
		struct esdm_cdev_conn *conn = &esdm_cdev_conns[i];

		if (conn->sock)
			sock_release(conn->sock);
		mutex_destroy(&conn->lock);
	}
}
