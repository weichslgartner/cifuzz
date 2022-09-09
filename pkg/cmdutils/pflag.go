package cmdutils

import (
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
)

func MarkFlagsRequired(cmd *cobra.Command, flags ...string) {
	for _, flag := range flags {
		err := cmd.MarkFlagRequired(flag)
		if err != nil {
			panic(err)
		}
	}
}

func ViperMustBindPFlag(key string, flag *pflag.Flag) {
	err := viper.BindPFlag(key, flag)
	if err != nil {
		panic(err)
	}
}

// AddBundleFlags adds the flags shared by the bundle and remote-run commands
func AddBundleFlags(cmd *cobra.Command) {
	cmd.Flags().Uint("build-jobs", 0, "Maximum number of concurrent processes to use when building.\nIf argument is omitted the native build tool's default number is used.\nOnly available when the build system is CMake.")
	cmd.Flags().Lookup("build-jobs").NoOptDefVal = "0"
	// TODO(afl): Also link to https://github.com/AFLplusplus/AFLplusplus/blob/stable/dictionaries/README.md
	cmd.Flags().String("dict", "", "A `file` containing input language keywords or other interesting byte sequences.\nSee https://llvm.org/docs/LibFuzzer.html#dictionaries.")
	// TODO(afl): Also link to https://www.mankier.com/8/afl-fuzz
	cmd.Flags().StringArray("engine-arg", nil, "Command-line `argument` to pass to the fuzzing engine.\nSee https://llvm.org/docs/LibFuzzer.html#options.")
	cmd.Flags().StringArray("fuzz-test-arg", nil, "Command-line `argument` to pass to the fuzz test.")
	// TODO(afl): Also link to https://aflplus.plus/docs/fuzzing_in_depth/#a-collecting-inputs
	cmd.Flags().StringArrayP("seed-corpus", "s", nil, "A `directory` containing sample inputs for the code under test.\nSee https://llvm.org/docs/LibFuzzer.html#corpus.")
	cmd.Flags().Duration("timeout", 0, "Maximum time to run the fuzz test, e.g. \"30m\", \"1h\". The default is to run indefinitely.")
}
