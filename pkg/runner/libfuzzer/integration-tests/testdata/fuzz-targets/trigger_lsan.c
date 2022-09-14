#include <stdlib.h>

void *p;

int LLVMFuzzerTestOneInput(const char *data, size_t len) {
  // Don't crash if the input is empty, so that we can test that the
  // fuzzer correctly emits the test input that caused the crash.
  if (len == 0) return 0;

  // Also don't crash if the input is the AFL input seed, because AFL
  // refuses to run without input seeds that don't crash the target
  if (len == 1 && data[0] == '?') return 0;

  // Trigger a memory leak
  p = malloc(7);
  p = 0; // The memory is leaked here.

  return 0;
}
