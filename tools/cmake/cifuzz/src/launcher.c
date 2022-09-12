#include <stdio.h>
#include <stdlib.h>

#if defined(_WIN32)
#define POSIX_EXECLP _execlp
#include <process.h>
#else
#define POSIX_EXECLP execlp
#include <unistd.h>
#endif

/*
 * If users launch a fuzz test binary directly, e.g. from the IDE, we want to run cifuzz instead of the raw fuzzer
 * binary. Since we also want cifuzz and the IDE to share a build directory, we can't implement this distinction at
 * compile-time - the fuzz test binary must be the same in both cases.
 *
 * Instead, we set the NO_CIFUZZ environment variable in cifuzz to signal to the fuzz test that it is already
 * running in cifuzz and replace the current process with cifuzz if the variable isn't set.
 *
 * The tricky part is where to execute this logic: -fsanitize=fuzzer provides a main function and the user may use
 * LLVMFuzzerInitialize themselves, so we can't easily use those. We could use constructors in C++, but MSVC requires
 * potentially fragile hacks to get the equivalent of __attribute__((constructor)) in C. Instead, we (ab)use the fact
 * that libFuzzer calls a specific MSan callback very early in its initialization procedure:
 * https://github.com/llvm/llvm-project/blob/2312b747b87300d94e834f257835ce93d36037cf/compiler-rt/lib/fuzzer/FuzzerDriver.cpp#L649
 *
 * This hack will break once we support MemorySanitizer and want to offer the launcher functionality for fuzz tests
 * instrumented with it - unlikely to happen.
 *
 * A downside of this hack is that LLVMFuzzerInitialize is still run - it doesn't matter too much since we replace the
 * process with cifuzz right after, but it may emit output.
 */
#ifdef __cplusplus
extern "C"
#endif
void __msan_scoped_disable_interceptor_checks() {
  if (getenv("NO_CIFUZZ")) {
    /* Running within cifuzz, behave like a regular libFuzzer fuzz target. */
    return;
  }
  /* Not running within cifuzz, replace the process with cifuzz running this fuzz test. */
  #ifdef __cplusplus
  // Prevent old-style-casting warning for cpp build
  POSIX_EXECLP("cifuzz", /*argv[0]=*/ "cifuzz", "run", CIFUZZ_TEST_NAME, static_cast<char*>(0));
  #else
  POSIX_EXECLP("cifuzz", /*argv[0]=*/ "cifuzz", "run", CIFUZZ_TEST_NAME, (char*)0);
  #endif
  /* Only reached if execl failed. */
  perror("Failed to execute cifuzz");
  printf("To start fuzzing, ensure that cifuzz is contained in PATH and execute:\n\n    cifuzz run %s\n\n", CIFUZZ_TEST_NAME);
  printf("If you really want to start the raw fuzzer binary, set NO_CIFUZZ=1.\n");
  exit(1);
}
