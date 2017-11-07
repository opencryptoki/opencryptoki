#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <memory.h>
#include <sys/wait.h>

#define MAX_SLOTS	1024
#define OCK_LIB		"libopencryptoki.so"
#define PROGNAME	"OCK_MULTI_TOKEN_TEST"

/* Usage */
const char *usage =
        "\nOCK_MULTI_TOKEN_TEST - multi token test utility using the "\
	"opencryptoki test framework.\n\n"
        "  Options:\n"
        "       -s  N          Number of Slots to test in parallel\n"
        "       -p  N          USER PIN (must be the same for all tokens)\n"
        "       -f  P          Path to an OCK test case\n"
        "       -h             Print this help text.\n\n"
	"  Example: ock_multi_token_tests -s 5 -p <userPIN> -f <pathToOpencryptoki>/testcases/crypto/aes_tests\n\n";

int main(int argc, char **argv)
{
	pid_t  pid;
	int status, i, c, rc = 0, slots = 1;
	char *pin = NULL, *path = NULL, *testcase = NULL;
	int pin_len = 0, path_len = 0;
	char cmd[512];

	while ((c = getopt(argc, argv, "f:s:p:3hay:sokx:")) != -1) {
		switch (c) {
		case 's': /* slots */
			sscanf(optarg, "%d", &slots);
			if (slots < 0 || slots > MAX_SLOTS) {
				fprintf(stderr, "Invalid number of slots. "\
					"Maximum slots supported: %d\n",
					MAX_SLOTS);
				exit(1);
			}
			break;
		case 'p': /* PIN */
			pin = malloc(strlen(optarg)+1);
			pin_len = strlen(optarg);
			strcpy((char*)pin,optarg);
			pin[pin_len] = '\0';
			break;
		case 'f': /* Test case path */
			path = malloc(strlen(optarg)+1);
			path_len = strlen(optarg);
			strcpy((char*)path,optarg);
			path[path_len] = '\0';

			break;
		case 'h':
			puts(usage);
			exit (0);
			break;
		}
	}
	if (pin == NULL) {
		printf("No user PIN specified!\n");
		puts(usage);
		exit(1);
	}

	if (path == NULL) {
		printf("No test case specified!\n");
		puts(usage);
		exit(1);
	}

	for (i = 1; i <= slots; i++) {
		pid = fork();

		if (pid == -1) {
			/* Error, fork failed */
			fprintf(stderr, "Fork failed, error %d\n", errno);
			exit(EXIT_FAILURE);
		}
		else if (pid == 0) {
			/* Child process */
			testcase = (strrchr(path, '/')) + 1;
			sprintf(cmd, "%s%s; %s -slot %d > %s_rslt_slot_%d.txt",
				"export PKCS11_USER_PIN=", pin, path, i,
				testcase, i);
			rc = system(cmd);
			if (rc)
				printf("Execution of test case %s failed "\
				       "(0x%02x)!\n", cmd, rc);
			_exit(0);
		}
		else {
			/* Parent process */
			waitpid(pid, &status, 0);
			if (status != 0) {
				printf("The child process terminated!\n");
			}
			continue;
		}

	}

	if (pin)
		free(pin);
	if (path)
		free(path);

	return 0;
}
