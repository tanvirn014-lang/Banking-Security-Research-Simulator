package main

import (
	"fmt"
	"os"
)

const version = "banksec-lab v0.1.0-dev"

// defaultEnv is used by a real CLI invocation (main); tests construct
// their own cliEnv pointed at an isolated temp directory.
var defaultEnv = cliEnv{DataDir: "data", ProfilePath: "configs/hardened.json"}

// runMain parses the command-line arguments and returns the text to print.
// --version is handled here directly; every other command is a banking
// operation dispatched to runCLI.
func runMain(args []string) (string, error) {
	if len(args) == 1 && args[0] == "--version" {
		return version + "\n", nil
	}
	return runCLI(defaultEnv, args)
}

func main() {
	out, err := runMain(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	fmt.Print(out)
}
