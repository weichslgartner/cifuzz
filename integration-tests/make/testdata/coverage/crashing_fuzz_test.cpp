#include <assert.h>

#include <iostream>

#include <cifuzz/cifuzz.h>

FUZZ_TEST(const uint8_t *data, size_t size) {
  if (size < 1) {
    return;
  }
  switch (data[0]) {
    case 'A':
      std::cout << 'A' << std::endl;
      break;
    case 'B':
      std::cout << 'B' << std::endl;
      break;
    case 'C':
      std::cout << "C (assert failure)" << std::endl;
      assert(1 == 0);
      break;
    case 'D':
      std::cout << 'D' << std::endl;
      break;
    case 'E':
      std::cout << 'E' << std::endl;
      break;
    case 'F':
      std::cout << "F (exit)" << std::endl;
      exit(1);
      break;
    case 'G':
      std::cout << 'G' << std::endl;
      break;
    case 'H':
      std::cout << 'H' << std::endl;
      break;
    case 'I':
      std::cout << "I (segfault)" << std::endl;
      *((volatile char *) 0) = 1;
      break;
    case 'J':
      std::cout << 'J' << std::endl;
      break;
  }
}
