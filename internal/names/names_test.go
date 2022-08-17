package names

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeterminsticName(t *testing.T) {
	assert.Equal(t, "upbeat_mirzakhani", GetDeterministicName([]byte("fc75")))
	assert.Equal(t, "gallant_stonebraker", GetDeterministicName([]byte("fc7598c04e2ffdc36c3ff70428fd98912ffb07a8")))
	assert.Equal(t, "fervent_lovelace", GetDeterministicName([]byte("")))
}
