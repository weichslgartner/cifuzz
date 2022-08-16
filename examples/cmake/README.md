# cifuzz cmake example
This is a simple CMake based project, already configured with 
**cifuzz**. It should quickly produce a finding, but slow enough to 
see the progress of the fuzzer.

To start make sure you installed **cifuzz** according to the 
main [README](../../README.md).

You can start the fuzzing with
```bash
cifuzz run my_fuzz_test
```

## Create Regression Test
After you have discovered a finding, you may want to include this as part of a regression test. This can be done by building the fuzz test (my_fuzz_test) as a replayer binary. This requires some additional options be passed to cmake:

```bash
cmake -S . -B build -DCIFUZZ_ENGINE="replayer" -DCIFUZZ_SANITIZERS="address;undefined" -DCIFUZZ_TESTING:BOOL="ON" -DCMAKE_BUILD_RPATH_USE_ORIGIN:BOOL="ON" -DCMAKE_BUILD_TYPE="RelWithDebInfo"
make -C build
```

To execute the replayer binary, run `./build/my_fuzz_test`
When you run the replayer binary, it will use any findings located in the my_fuzz_test_seed_corpus directory as input. 
