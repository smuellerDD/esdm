/*
 * Copyright (C) 2026, Markus Theil <theil.markus@gmail.com>
 *
 * License: see LICENSE file in root directory
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

/*
 * esdm-es-pkcs11 against a client speaking the protocol of the external
 * entropy sources, as the ESDM does.
 *
 * - What it cannot run with, it refuses to start with, never repeating a PIN
 *   given on the command line by mistake.
 * - A module that cannot be loaded is no reason not to serve: the daemon
 *   credits nothing and says why in its status.
 * - Against a SoftHSM token: the token of the label is used and logged in to
 *   with the PIN of a file or of a systemd credential; INFO declares "PKCS#11"
 *   and the label, and the rate; GET_ENTROPY claims all bits of its data,
 *   leaving the rate to the ESDM; STATUS is valid JSON whatever bytes the
 *   label holds.
 * - A PIN the token refuses is tried once and never again; the token is used
 *   without a login then.
 * - A failed C_GenerateRandom drops the token, which is looked for again on
 *   the next request.
 * - A token repeating its output is credited with nothing until a self test
 *   passes again.
 * - A token not there at start up is looked for on demand, at most every
 *   ESDM_PKCS11_RETRY_INTERVAL_SEC.
 *
 * The token part is skipped without softhsm2-util on the path.
 *
 * Usage: es_pkcs11_test <esdm-es-pkcs11> <es_pkcs11_shim module>
 */

#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>

#include "common_test.h"
#include "es_ext_test_client.h"
#include "es_pkcs11_test_util.h"

/* As esdm_es_pkcs11.c has it */
#define RETRY_INTERVAL_SEC 5
#define TOKEN_ARGS(label) "--module", pk.shim, "--token_label", label

static const char *const test_cred[] = { "CREDENTIALS_DIRECTORY=credentials",
					 NULL };
static struct es_ext_test_client test_client = { .fd = -1 };

/* Lines of daemon.log containing @what */
static inline unsigned int pk_log_count(const char *what)
{
	unsigned int count = 0;
	char line[1024];
	FILE *f = fopen("daemon.log", "re");

	while (f && fgets(line, sizeof(line), f))
		count += !!strstr(line, what);
	if (f)
		fclose(f);
	return count;
}

#define test_ask(type, length)                                                 \
	es_ext_test_client_ask(&test_client, ESDM_ES_EXT_PROTO_##type, length)

static void test_info(const char *name, uint32_t rate)
{
	char got[ESDM_ES_EXT_NAME_MAX + 1] = "";
	uint32_t declared = ~0U;

	CHECK_EQ(es_ext_test_client_info(&test_client, got, sizeof(got),
					 &declared),
		 0);
	CHECK_STR_EQ(got, name);
	CHECK_EQ(declared, rate);
}

/*
 * Check the members of the "plugin" part of STATUS: pairs of the key and the
 * value, NULL terminated - text a string member contains, else the JSON of
 * the member, "true" or "null"
 */
static void test_status(const char *what, ...)
{
	struct json_object *root, *st = NULL, *val;
	const char *text, *key, *exp, *got;
	va_list ap;

	root = es_ext_test_client_status(&test_client,
					 ESDM_ES_EXT_PROTO_STATUS_MAX);
	text = json_object_to_json_string(root);
	CHECK(json_object_object_get_ex(root, "plugin", &st) && st,
	      "%s: no valid STATUS: %s", what, text);
	va_start(ap, what);
	while (st && (key = va_arg(ap, const char *))) {
		exp = va_arg(ap, const char *);
		val = NULL;
		json_object_object_get_ex(st, key, &val);
		got = json_object_is_type(val, json_type_string) ?
			      json_object_get_string(val) :
			      json_object_to_json_string(val);
		CHECK(json_object_is_type(val, json_type_string) ?
			      !!strstr(got, exp) :
			      !strcmp(got, exp),
		      "%s: %s is %s, not %s, in %s", what, key, got, exp, text);
	}
	va_end(ap);
	json_object_put(root);
}

static bool test_connect(const char *const *args, const char *const *env)
{
	bool ret;

	es_ext_test_client_close(&test_client);
	ret = pk_start(args, env) &&
	      !es_ext_test_client_open(&test_client, pk.socket);
	CHECK(ret, "cannot connect to esdm-es-pkcs11");
	return ret;
}

static void test_stop(void)
{
	es_ext_test_client_close(&test_client);
	CHECK(pk_stop(),
	      "esdm-es-pkcs11 did not end cleanly on SIGTERM, removing its socket");
}

/* What the daemon cannot run with: refused with the message @expect */
static void test_options(void)
{
	static const struct {
		bool cred;
		const char *args[4];
		const char *expect;
	} refused[] = {
		{ 0, { "--module", "" }, "No PKCS#11 module" },
		{ 0, { "--entropy_rate", "257" }, "--entropy_rate takes" },
		{ 0, { "--name", "a\x01name" }, "--name takes" },
		{ 0, { "--pin_file", "no-such-pin" }, "Cannot open the PIN" },
		{ 0, { "--pin_file", "empty-pin" }, "is empty" },
		{ 0, { "--pin_file", "credentials" }, "is no regular file" },
		{ 0, { "--pin_file", "two-lines" }, "more than one line" },
		{ 0, { "--pin_credential", "pkcs11-pin" }, "no credentials" },
		{ 1, { "--pin_credential", "../pin" }, "name of a credential" },
		{ 1, { "--pin_credential", "nope" }, "Cannot open the PIN" },
		{ 1,
		  { "--pin_file", "pin", "--pin_credential", "pkcs11-pin" },
		  "exclude each other" },
		{ 0, { "--pin_file" }, "--pin_file needs an argument" },
		/* A PIN given by mistake is no option it may be repeated in */
		{ 0, { PK_TOKEN_PIN }, "not repeated" },
		{ 0, { "--pin=" PK_TOKEN_PIN }, "not repeated" },
		{ 0, { "--" PK_TOKEN_PIN }, "not repeated" },
		{ 0, { "--verbose=" PK_TOKEN_PIN }, "not repeated" },
	};
	unsigned int i, j;
	int status;

	CHECK(!pk_write_file("empty-pin", "", 0600) &&
		      !pk_write_file("two-lines",
				     PK_TOKEN_PIN "\n" PK_TOKEN_PIN "\n", 0600),
	      "cannot write the PIN files");

	for (i = 0; i < sizeof(refused) / sizeof(refused[0]); i++) {
		const char *args[] = { "--module",
				       pk.shim,
				       refused[i].args[0],
				       refused[i].args[1],
				       refused[i].args[2],
				       refused[i].args[3],
				       NULL };
		pid_t pid = pk_daemon(args, refused[i].cred ? test_cred : NULL);

		status = -1;
		for (j = 0; pid > 0 && j < 1000 &&
			    waitpid(pid, &status, WNOHANG) != pid;
		     j++)
			es_ext_test_sleep_ms(10);
		if (j == 1000)
			es_ext_test_terminate(pid);
		CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 1 &&
			      access(pk.socket, F_OK),
		      "%s: esdm-es-pkcs11 did not refuse to start", args[2]);
		CHECK(pk_log_count(refused[i].expect) &&
			      !pk_log_count(PK_TOKEN_PIN),
		      "%s: not refused with \"%s\" alone", args[2],
		      refused[i].expect);
	}
}

/* A module that cannot be loaded: the daemon serves, credits nothing */
static void test_no_module(void)
{
	/* "PKCS#11 " and this label make no name of up to 32 bytes */
	const char *const args[] = { "--module", "/nonexistent/pkcs11.so",
				     "--token_label",
				     "a-token-label-of-thirty-bytes-x", NULL };

	if (!test_connect(args, NULL))
		return;
	test_info("PKCS#11", ESDM_PKCS11_ENTROPY_RATE);
	CHECK_EQ(test_ask(GET_ENTROPY, 32), -ENODEV);
	/* No token to test is no failure */
	CHECK_EQ(test_ask(SELFTEST, 0), 0);
	test_status("no module", "module", "/nonexistent/pkcs11.so",
		    "token_label", "a-token-label-of-thirty-bytes-x",
		    "token_present", "false", "logged_in", "false", "token",
		    "null", "slot", "null", "pin", "none", "last_error",
		    "cannot be loaded", NULL);
	test_stop();
}

/*
 * The token of the test, logged in to with the PIN of @args or @env, and
 * found and logged in to again after a failed C_GenerateRandom
 */
static void test_token(const char *what, const char *const *args,
		       const char *const *env)
{
	uint8_t first[64] = { 0 };
	unsigned int i, zero = 0;

	if (!test_connect(args, env))
		return;
	test_info("PKCS#11 " PK_TOKEN_LABEL, 200);

	CHECK_EQ(test_ask(GET_ENTROPY, sizeof(first)), 0);
	CHECK_EQ(test_client.bits, sizeof(first) * 8);
	if (test_client.data)
		memcpy(first, test_client.data, sizeof(first));
	for (i = 0; i < sizeof(first); i++)
		zero += !first[i];
	CHECK_EQ(test_ask(GET_ENTROPY, sizeof(first)), 0);
	CHECK(test_client.data &&
		      memcmp(first, test_client.data, sizeof(first)) &&
		      zero < sizeof(first),
	      "%s: the token repeats itself, or delivers zeros", what);
	CHECK_EQ(test_ask(SELFTEST, 0), 0);
	test_status(what, "token", PK_TOKEN_LABEL, "token_label",
		    PK_TOKEN_LABEL, "token_present", "true", "logged_in",
		    "true", "pin", "set", "repetition_test", "passed",
		    "last_error", "null", NULL);
	CHECK_EQ(pk_log_count("C_Login user 1 rv 0x0"), 1);
	CHECK_EQ(pk_log_count("C_Login"), 1);

	CHECK(!pk_write_file("fail", "", 0600), "cannot fail the token");
	CHECK_EQ(test_ask(GET_ENTROPY, 32), -EIO);
	test_status(what, "token_present", "false", "last_error",
		    "C_GenerateRandom failed", NULL);
	unlink("fail");
	CHECK_EQ(test_ask(GET_ENTROPY, 32), 0);
	test_status(what, "token_present", "true", "logged_in", "true", NULL);
	CHECK_EQ(pk_log_count("C_Login user 1 rv 0x0"), 2);
	test_stop();
}

/*
 * The PIN of a file - one that every user reads is warned about, one of a
 * group is not - and of a systemd credential, of the default name or another
 */
static void test_pin(void)
{
	static const mode_t modes[] = { 0600, 0640, 0644 };
	const char *args[] = {
		"--pin_file",	  "pin", TOKEN_ARGS(PK_TOKEN_LABEL),
		"--entropy_rate", "200", NULL
	};
	unsigned int i;

	for (i = 0; i < sizeof(modes) / sizeof(modes[0]); i++) {
		CHECK(!chmod("pin", modes[i]), "cannot chmod the PIN file");
		test_token("PIN file", args, NULL);
		CHECK_EQ(pk_log_count("open to every user"),
			 modes[i] & S_IROTH ? 1 : 0);
	}

	CHECK(!pk_write_file("credentials/pkcs11-pin", PK_TOKEN_PIN, 0400),
	      "cannot write the credential");
	test_token("credential", args + 2, test_cred);
	unlink("credentials/pkcs11-pin");

	CHECK(!pk_write_file("credentials/my-pin", PK_TOKEN_PIN "\n", 0400),
	      "cannot write the credential");
	args[0] = "--pin_credential";
	args[1] = "my-pin";
	test_token("named credential", args, test_cred);
}

/*
 * A PIN the token refuses is tried once, never again - not when the token is
 * looked for again - and the token is used without a login
 */
static void test_wrong_pin(void)
{
	const char *const args[] = { TOKEN_ARGS(PK_TOKEN_LABEL), "--pin_file",
				     "wrong-pin", NULL };

	if (!test_connect(args, NULL))
		return;
	/* SoftHSM hands out random numbers without a login */
	CHECK_EQ(test_ask(GET_ENTROPY, 32), 0);
	test_status("wrong PIN", "token_present", "true", "logged_in", "false",
		    "pin", "refused", NULL);

	CHECK(!pk_write_file("fail", "", 0600), "cannot fail the token");
	CHECK_EQ(test_ask(GET_ENTROPY, 32), -EIO);
	unlink("fail");
	CHECK_EQ(test_ask(GET_ENTROPY, 32), 0);
	test_status("wrong PIN", "token_present", "true", "logged_in", "false",
		    NULL);

	CHECK_EQ(pk_log_count("C_Login"), 1);
	CHECK_EQ(pk_log_count("rv 0x0"), 0);
	CHECK_EQ(pk_log_count("the PIN is not tried again"), 1);
	test_stop();
}

/* Repeated output fails the self test, and is credited with nothing */
static void test_repetition(void)
{
	const char *const args[] = { TOKEN_ARGS(PK_TOKEN_LABEL), NULL };
	const uint32_t credited = 32 * 8;

	if (!test_connect(args, NULL))
		return;
	CHECK_EQ(test_ask(GET_ENTROPY, 32), 0);
	CHECK_EQ(test_client.bits, credited);

	CHECK(!pk_write_file("repeat", "", 0600), "cannot repeat the token");
	CHECK_EQ(test_ask(SELFTEST, 0), -EFAULT);
	CHECK_EQ(test_ask(GET_ENTROPY, 32), 0);
	CHECK_EQ(test_client.bits, 0);
	test_status("repeated", "repetition_test", "failed", "last_error",
		    "repeated", NULL);

	/* Delivering again is not enough, a test has to pass */
	unlink("repeat");
	CHECK_EQ(test_ask(GET_ENTROPY, 32), 0);
	CHECK_EQ(test_client.bits, 0);
	CHECK_EQ(test_ask(SELFTEST, 0), 0);
	CHECK_EQ(test_ask(GET_ENTROPY, 32), 0);
	CHECK_EQ(test_client.bits, credited);
	test_status("passed again", "repetition_test", "passed", "last_error",
		    "null", NULL);
	test_stop();
}

/*
 * Without a label the first token with an RNG is used. A label that is no
 * UTF-8 and holds a control character makes no name, and valid JSON.
 */
static void test_labels(void)
{
	const char *const first[] = { "--module", pk.shim, NULL };
	const char *const odd[] = { TOKEN_ARGS("\xff\x1b-esdm"), NULL };

	/* A build with a default label looks for that one */
	if (!ESDM_PKCS11_TOKEN_LABEL[0] && test_connect(first, NULL)) {
		test_info("PKCS#11", ESDM_PKCS11_ENTROPY_RATE);
		CHECK_EQ(test_ask(GET_ENTROPY, 32), 0);
		test_status("first", "token", PK_TOKEN_LABEL, "token_label",
			    "null", NULL);
		test_stop();
	}

	if (!pk_init_token(odd[3])) {
		printf("softhsm2-util refuses the odd label - skipped\n");
		return;
	}
	if (!test_connect(odd, NULL))
		return;
	test_info("PKCS#11", ESDM_PKCS11_ENTROPY_RATE);
	CHECK_EQ(test_ask(GET_ENTROPY, 32), 0);
	/* "\?" as "??-" would be a trigraph */
	test_status("odd label", "token", "?\?-esdm", "token_label", "?\?-esdm",
		    NULL);
	test_stop();
}

/* Without --module, the module of the build - tested if it is SoftHSM */
static void test_default_module(void)
{
	const char *const args[] = { "--token_label", PK_TOKEN_LABEL, NULL };

	if (!strstr(ESDM_PKCS11_MODULE_PATH, "softhsm") ||
	    access(ESDM_PKCS11_MODULE_PATH, R_OK) || !test_connect(args, NULL))
		return;
	CHECK_EQ(test_ask(GET_ENTROPY, 32), 0);
	test_status("default module", "module", ESDM_PKCS11_MODULE_PATH,
		    "token", PK_TOKEN_LABEL, NULL);
	test_stop();
}

/* A token not there at start up: looked for at most every retry interval */
static void test_token_appears(void)
{
	const char *const args[] = { TOKEN_ARGS("esdm-late-token"), NULL };

	if (!test_connect(args, NULL))
		return;
	test_info("PKCS#11 esdm-late-token", ESDM_PKCS11_ENTROPY_RATE);
	test_status("no token", "token_present", "false", "pin", "none",
		    "last_error", "no usable token", NULL);
	/* Spends the first look-up */
	CHECK_EQ(test_ask(GET_ENTROPY, 32), -ENODEV);

	CHECK(pk_init_token(args[3]), "cannot create the late token");
	CHECK_EQ(test_ask(GET_ENTROPY, 32), -ENODEV);

	es_ext_test_sleep_ms((RETRY_INTERVAL_SEC + 1) * 1000);
	CHECK_EQ(test_ask(GET_ENTROPY, 32), 0);
	CHECK_EQ(test_client.bits, 32 * 8);
	test_status("late token", "token", args[3], "logged_in", "false",
		    "last_error", "null", NULL);
	CHECK_EQ(pk_log_count("C_Login"), 0);
	test_stop();
}

int main(int argc, char *argv[])
{
	int ret;

	if (argc != 3) {
		printf("Usage: %s <esdm-es-pkcs11> <shim module>\n", argv[0]);
		return 1;
	}

	ret = pk_setup(argv[1], argv[2]);
	if (ret == 1) {
		printf("cannot set up the test directory and token\n");
	} else {
		test_options();
		test_no_module();
		if (!ret) {
			test_pin();
			test_wrong_pin();
			test_repetition();
			test_labels();
			test_default_module();
			/* Last: it creates the token it looks for */
			test_token_appears();
		}
		ret = common_test_failures || !ret ?
			      common_test_result("es_pkcs11") :
			      ret;
	}

	es_ext_test_client_close(&test_client);
	pk_cleanup();
	return ret;
}
