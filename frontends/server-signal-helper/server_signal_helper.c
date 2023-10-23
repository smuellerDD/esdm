/*
 * Copyright (C) 2023, Markus Theil <theil.markus@gmail.com>
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

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <esdm_rpc_client.h>

static bool signal_suspend(char *pidfile_path)
{
	char pid_string[30] = { 0 };
	FILE *pidfile = NULL;
	size_t read_ret;
	pid_t pid = -1;

	/* read PID */
	if (pidfile_path == NULL) {
		return false;
	}

	pidfile = fopen(pidfile_path, "r");
	if (pidfile == NULL) {
		return false;
	}
	read_ret = fread(&pid_string, 1, sizeof(pid_string) - 1, pidfile);
	if (read_ret == 0 || ferror(pidfile)) {
		fprintf(stderr, "Error reading PID");
		fclose(pidfile);
		return false;
	}
	fclose(pidfile);

	pid = (pid_t)strtol(pid_string, NULL, 10);
	if (errno) {
		perror("PID conversion failed");
		return false;
	}

	fprintf(stdout, "Signal suspend to ESDM\n");
	return kill(pid, SIGUSR1) == 0;
}

static bool signal_resume()
{
	int ret;

	if (esdm_rpcc_init_unpriv_service(NULL) != 0)
		return false;
	fprintf(stdout, "Signal resume to ESDM\n");

	/* write empty byte array to trigger reseed after resume */
	unsigned char dummy_data[1] = { 0 };

	esdm_invoke(esdm_rpcc_write_data(dummy_data, sizeof(dummy_data)));

	esdm_rpcc_fini_unpriv_service();

	return ret == 0;
}

static void usage()
{
	fprintf(stderr,
		"esdm-server-signal-helper [--resume] [--suspend] [--pid PIDFILE] [--help]\n");
}

int main(int argc, char **argv)
{
	int c = 0;
	char *pidfile_path = NULL;
	bool suspend = false;
	bool resume = false;
	bool help = false;
	int ret = EXIT_SUCCESS;

	while (1) {
		int opt_index = 0;
		static struct option opts[] = { { "pid", 1, 0, 0 },
						{ "suspend", 0, 0, 0 },
						{ "resume", 0, 0, 0 },
						{ "help", 0, 0, 0 },
						{ 0, 0, 0, 0 } };
		c = getopt_long(argc, argv, "p:srh", opts, &opt_index);
		if (-1 == c)
			break;
		switch (c) {
		case 0:
			switch (opt_index) {
			case 0:
				/* pid */
				pidfile_path = optarg;
				break;
			case 1:
				/* suspend */
				suspend = true;
				break;
			case 2:
				/* resume */
				resume = true;
				break;
			case 3:
				/* help */
				help = true;
				break;
			}
			break;
		case 'p':
			pidfile_path = optarg;
			break;
		case 's':
			suspend = true;
			break;
		case 'r':
			resume = true;
			break;
		case 'h':
			help = true;
			break;
		}
	}

	if (suspend && !signal_suspend(pidfile_path)) {
		fprintf(stderr, "Failure during suspend signaling\n");
		ret = EXIT_FAILURE;
	} else if (resume && !signal_resume()) {
		fprintf(stderr, "Failure during resume signaling\n");
		ret = EXIT_FAILURE;
	} else if (help) {
		usage();
		ret = EXIT_FAILURE;
	} else if (errno) {
		perror("Unknown mode or error:");
		usage();
		ret = EXIT_FAILURE;
	}

	return ret;
}
