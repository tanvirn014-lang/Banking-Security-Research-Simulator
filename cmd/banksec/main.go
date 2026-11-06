package main

import (
	"fmt"
	"os"
)

const version = "banksec-lab v0.1.0-dev"

// runMain parses the command-line arguments and returns the text to print.
// Only the --version flag is supported for now.
func runMain(args []string) (string, error) {
	if len(args) == 1 && args[0] == "--version" {
		return version + "\n", nil
	}
	return "", fmt.Errorf("unknown arguments: %v", args)
}

func main() {
	out, err := runMain(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Print(out)
}
