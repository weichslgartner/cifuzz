#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

// Includes argv[0] and the working directory.
#define NUM_FIXED_ARGS 2u

// Executes argv[2] with arguments listed after the separator and the
// environment variables listed before the separator after changing the working
// directory to argv[1].
int main(int argc, char **argv) {
  if (argc < 4) {
    fprintf(stderr,
            "Usage: %s <directory> <env_name1=env_value1>... -- "
            "<executable_path> <executable_arg1>...\n",
            argv[0]);
    return 1;
  }

  size_t separator_index = NUM_FIXED_ARGS;
  while (separator_index < argc && strcmp("--", argv[separator_index]) != 0) {
    separator_index++;
  }
  if (separator_index >= argc - 1) {
    fprintf(stderr,
            "expected arguments: -- <executable_path> <executable_arg1>...\n");
    return 1;
  }

  // All variables are listed between the fixed first arguments and the
  // separator. We also have to account for the terminating NULL pointer.
  size_t num_env_vars = separator_index - NUM_FIXED_ARGS;
  size_t envp_length = num_env_vars + 1;
  char **envp = malloc(envp_length * sizeof(char *));
  if (envp == NULL) {
    fprintf(stderr, "malloc failed");
    return 1;
  }
  envp[envp_length - 1] = NULL;
  for (size_t i = 0; i < num_env_vars; i++) {
    envp[i] = argv[NUM_FIXED_ARGS + i];
  }

  if (chdir(argv[1]) == -1) {
    fprintf(stderr, "chdir(%s) failed: %s\n", argv[1], strerror(errno));
    return 1;
  }

  // Forward all arguments after the separator, which we know exists at this
  // point.
  char **executable_argv = argv + separator_index + 1;
  if (execve(*executable_argv, executable_argv, envp) == -1) {
    fprintf(stderr, "execve(%s) failed: %s\n", *executable_argv,
            strerror(errno));
    return 1;
  }
  // Not reached.
}
