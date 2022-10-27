package binary

import (
	"debug/elf"
	"runtime"

	"code-intelligence.com/cifuzz/pkg/log"
)

func SupportsLlvmProfileContinuousMode(binary string) bool {
	if runtime.GOOS == "darwin" {
		// No compile-time flags are required on macOS.
		return true
	}
	if runtime.GOOS != "linux" {
		// We do not know the level of support for platforms other than Linux
		// and macOS.
		return false
	}
	// On Linux, we need to parse the symbols of the binary to check whether it
	// has been built with the required compile-time flags
	// (-mllvm -runtime-counter-relocation).
	file, err := elf.Open(binary)
	if err != nil {
		log.Warnf("Failed to parse %s as an ELF file: %s", binary, err)
		// Continuous mode is best-effort, do not fail on "weird" binaries.
		return false
	}
	symbols, err := file.Symbols()
	if err != nil {
		log.Warnf("Failed to read ELF symbols from %s: %s", binary, err)
		return false
	}
	var biasVarAddress uint64
	var biasDefaultVarAddress uint64
	for _, symbol := range symbols {
		if symbol.Name == "__llvm_profile_counter_bias" {
			biasVarAddress = symbol.Value
		} else if symbol.Name == "__llvm_profile_counter_bias_default" {
			biasDefaultVarAddress = symbol.Value
		}
	}
	// Check taken from:
	// https://github.com/llvm/llvm-project/blob/846709b287abe541fcad42e5a54d37a41dae3f67/compiler-rt/lib/profile/InstrProfilingFile.c#L574
	return biasVarAddress != 0 && biasDefaultVarAddress != 0 && biasVarAddress != biasDefaultVarAddress
}
