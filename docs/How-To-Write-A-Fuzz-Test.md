# How to write a fuzz test

## Setup

### CMake
When using `cifuzz init` and `cifuzz create` the commands will tell you 
which manual steps are necessary to use the cifuzz CMake integration inside
your existing project. Usually you also have to add instructions in your 
CMakeLists.txt file to link the fuzz test with  the software under test 
(e.g. use the `target_link_libraries directive`). 
The `add_fuzz_test` directive can be treated like `add_executable`.


## How to convert/cast the fuzzer data into the data types you need

You might have to convert/cast the input parameters to other types to call your
functions. A useful tool for this is The
[FuzzedDataProvider](https://github.com/google/fuzzing/blob/master/docs/split-inputs.md#fuzzed-data-provider).

<details>
<summary>C/C++</summary>

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
</details>

<details>
<summary>Java</summary>
For Java, you can use the FuzzedDataProvider which is part of the Jazzer API
package that is automatically downloaded by maven/gradle respectively if set up
properly after cifuzz init. 

An example can look like this:

```java
import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;

public class FuzzTestCase {
    @FuzzTest
    void myFuzzTest(FuzzedDataProvider data) {
        int a = data.consumeInt();
        int b = data.consumeInt();
        String c = data.consumeRemainingAsString();

        myFunction(a, b, c);
    }
}
```
</details>

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

You can also run the fuzz tests in regression test mode from the CLI:

```bash
cmake --preset="cifuzz (Regression Test)"
cmake --build --preset="cifuzz (Regression Test)"
ctest --preset="cifuzz (Regression Test)"
```

You can find the generated binaries in
`.cifuzz-build/replayer/address+undefined/`.
