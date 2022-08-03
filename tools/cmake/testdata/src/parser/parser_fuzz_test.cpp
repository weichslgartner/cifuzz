#include <iostream>

#include "parser.h"
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

FUZZ_TEST_SETUP() {
  std::cout << "FUZZ_TEST_SETUP ran" << std::endl;
}

FUZZ_TEST(const std::uint8_t *data, std::size_t size) {
  FuzzedDataProvider fdp(data, size);
  parse(fdp.ConsumeRemainingBytesAsString());
}

extern "C" size_t LLVMFuzzerMutate(uint8_t *Data, size_t Size, size_t MaxSize);
// Simulate a custom mutator by invoking the default mutator directly.
extern "C" size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size, unsigned int seed) {
  (void) seed;
  return LLVMFuzzerMutate(data, size, max_size);
}
