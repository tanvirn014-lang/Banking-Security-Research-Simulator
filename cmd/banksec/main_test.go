package main

import "testing"

func TestVersionFlag(t *testing.T) {
	out, err := runMain([]string{"--version"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if out != "banksec-lab v0.1.0-dev\n" {
		t.Fatalf("got %q", out)
	}
}
