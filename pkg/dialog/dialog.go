package dialog

import (
	"sort"

	"atomicgo.dev/keyboard/keys"
	"github.com/pkg/errors"
	"github.com/pterm/pterm"
	"golang.org/x/exp/maps"
)

// Select offers the user a list of items (label:value) to select from and returns the value of the selected item
func Select(message string, items map[string]string) (string, error) {
	options := maps.Keys(items)
	sort.Strings(options)
	prompt := pterm.DefaultInteractiveSelect.WithOptions(options)
	prompt.DefaultText = message

	result, err := prompt.Show()
	if err != nil {
		return "", errors.WithStack(err)
	}

	return items[result], nil
}

// MultiSelect offers the user a list of items (label:value) to select from and returns the values of the selected items
func MultiSelect(message string, items map[string]string) ([]string, error) {
	options := maps.Keys(items)
	sort.Strings(options)

	prompt := pterm.DefaultInteractiveMultiselect.WithOptions(options)
	prompt.DefaultText = message
	prompt.Filter = false
	prompt.KeyConfirm = keys.Enter
	prompt.KeySelect = keys.Space

	selectedOptions, err := prompt.Show()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	sort.Strings(selectedOptions)

	var result []string
	for _, option := range selectedOptions {
		result = append(result, items[option])
	}

	return result, nil
}
