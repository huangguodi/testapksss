//go:build ios

package cmd

import "errors"

func ExecCmd(cmdStr string) (string, error) {
	return "", errors.New("exec command is not supported on ios")
}
