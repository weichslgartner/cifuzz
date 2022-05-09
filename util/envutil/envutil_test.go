package envutil

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAddToColonSeparatedList(t *testing.T) {
	// Check values successfully added
	require.Equal(t, "foo", AddToColonSeparatedList("", "foo"))
	require.Equal(t, "foo:bar", AddToColonSeparatedList("foo", "bar"))
	require.Equal(t, "foo:bar:baz", AddToColonSeparatedList("foo:bar", "baz"))
	// Check no duplicates added
	require.Equal(t, "foo", AddToColonSeparatedList("foo", "foo"))
	require.Equal(t, "foo:bar", AddToColonSeparatedList("foo:bar", "foo"))
	require.Equal(t, "foo:bar", AddToColonSeparatedList("foo:bar", "bar"))
	// Check no empty values added
	require.Equal(t, "foo", AddToColonSeparatedList("foo"))
	require.Equal(t, "foo", AddToColonSeparatedList("foo", ""))
	require.Equal(t, "foo:bar", AddToColonSeparatedList("foo:bar", ""))
	// Check multiple values added
	require.Equal(t, "foo:bar", AddToColonSeparatedList("", "foo", "bar"))
	require.Equal(t, "foo:bar:baz", AddToColonSeparatedList("foo", "bar", "baz"))
}

func TestSetenv(t *testing.T) {
	var env []string

	env, err := Setenv(env, "foo", "foo")
	require.NoError(t, err)
	require.Equal(t, env, []string{"foo=foo"})

	env, err = Setenv(env, "foo", "bar")
	require.NoError(t, err)
	require.Equal(t, env, []string{"foo=bar"})

	env, err = Setenv(env, "bao", "bab")
	require.NoError(t, err)
	require.Equal(t, env, []string{"foo=bar", "bao=bab"})
}

func TestGetenv(t *testing.T) {
	var val string

	val = Getenv([]string{}, "foo")
	require.Equal(t, val, "")

	val = Getenv([]string{"foo=bar"}, "foo")
	require.Equal(t, val, "bar")
}
