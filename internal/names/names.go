package names

import (
	"crypto/sha1"
	"encoding/binary"
	"math/rand"
	_ "unsafe"

	_ "github.com/moby/moby/pkg/namesgenerator"
)

// we have to work with fixed array sizes here as they are also
// used in the original package and there is no way to have a
// dynamically sized array
var (
	//go:linkname left github.com/moby/moby/pkg/namesgenerator.left
	left [108]string

	//go:linkname right github.com/moby/moby/pkg/namesgenerator.right
	right [237]string
)

// GetDeterministicName generates a name from the list of adjectives and
// surnames from Docker's namesgenerator package, formatted as
// "adjective_surname". For example 'focused_turing'.
// The name is chosen deterministically based on the specified seed.
func GetDeterministicName(seedValue []byte) string {
	hash := sha1.Sum(seedValue)
	source := rand.NewSource(int64(binary.BigEndian.Uint64(hash[:])))
	r := rand.New(source)
	return left[r.Intn(len(left))] + "_" + right[r.Intn(len(right))]
}
