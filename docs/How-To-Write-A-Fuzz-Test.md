# How to write a fuzz test

## How to convert/cast the fuzzer data into the data types you need

### C/C++

You might have to convert/cast the input parameters 
`const uint8_t *data, size_t size` to other types to call your 
functions. A useful tool for this is the [FuzzedDataProvider](https://github.com/google/fuzzing/blob/master/docs/split-inputs.md#fuzzed-data-provider).
If you use Clang/LLVM as your compiler of choice you can use it directly with 
`#include <fuzzer/FuzzedDataProvider.h>`, otherwise you can just copy 
the source file and add it to your project. 
An example can look like this:

``` cpp
#include <stdio.h>
#include <cifuzz/cifuzz.h>
#include <fuzzer/FuzzedDataProvider.h>

FUZZ_TEST_SETUP() {}

FUZZ_TEST(const uint8_t *data, size_t size) {

  FuzzedDataProvider fuzzed_data(data, size);
  int my_int = fuzzed_data.ConsumeIntegral<int8_t>();
  std::string my_string = fuzzed_data.ConsumeRandomLengthString();

  myFunction(my_int, my_string);
}
```

## Best Practices

### Regression Test / Replayer

After creating a new fuzz test we recommend to use the regression test
mode (see [README](../README.md#regression-testing)) to maintain a 
fast and responsive development cycle. The fuzz test has to be build
with so-called sanitizers, which track the execution at runtime to
be able to detect various errors.

It is recommended to use the provided CMake user presets, which can be
generated with `cifuzz integrate cmake`. Those provide a preset for
regression testing, which can be executed from within your IDE or in
the cli.

After selecting the preset the fuzz test is executed in regression
test mode.
![fuzz test in CMake](/docs/assets/cmake_clion.gif)

You can also use the regression preset to build the fuzz tests as
replayer binaries in the cli.

```bash
cmake --preset="cifuzz (Regression Test)"
cmake --build --preset="cifuzz (Regression Test)"
```

You can find the generated binaries in .cifuzz-build/replayer/address+undefined/.
