// Package storagebudget checks free filesystem bytes without reserving RAM.
package storagebudget

import "errors"

var ErrNoSpace = errors.New("insufficient storage headroom")
var ErrUnavailable = errors.New("storage capacity could not be verified")

// Check uses bytes available to the calling user, excluding privileged reserve.
// It is admission evidence, not a guarantee against concurrent writers.
func Check(path string, needed uint64) error {
	available, err := availableBytes(path)
	if err != nil {
		return ErrUnavailable
	}
	if available < needed {
		return ErrNoSpace
	}
	return nil
}
