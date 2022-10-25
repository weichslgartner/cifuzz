# cifuzz bazel example
This is a simple bazel based project, already configured with
**cifuzz**. It should quickly produce a finding, but slow enough to
see the progress of the fuzzer.

To start make sure you installed **cifuzz** according to the
main [README](../../README.md).

You can start the fuzzing with
```bash
cifuzz run //src:explore_me_fuzz_test
```

## Create regression test
After you have discovered a finding, you may want to include this as
part of a regression test. To replay findings from the
`src/explore_me_fuzz_test_inputs` directory:

```bash
bazel test --config=asan-replay //src:explore_me_fuzz_test --test_output=streamed
```

Note that this requires these lines in your `.bazelrc`:

```bash
# --config=asan-replay
build:asan-replay --@rules_fuzzing//fuzzing:cc_engine=@rules_fuzzing//fuzzing/engines:replay
build:asan-replay --@rules_fuzzing//fuzzing:cc_engine_instrumentation=none
build:asan-replay --@rules_fuzzing//fuzzing:cc_engine_sanitizer=asan
```
