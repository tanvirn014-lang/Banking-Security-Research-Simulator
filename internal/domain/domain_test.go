package domain

import (
	"go/build"
	"strings"
	"testing"
)

func TestRoleConstants_Distinct(t *testing.T) {
	if RoleAccountOwner == RolePrivilegedOperator {
		t.Fatalf("expected RoleAccountOwner and RolePrivilegedOperator to be distinct, both are %q", RoleAccountOwner)
	}
}

func TestNoInternalImports(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatalf("import package: %v", err)
	}
	// Covers every non-test file in the package (build.ImportDir's default
	// mode excludes _test.go files, which is fine: a _test.go importing
	// another internal package to write its own tests is normal and not
	// the cycle this guard protects against).
	for _, path := range pkg.Imports {
		if strings.HasPrefix(path, "banksec-lab/internal/") {
			t.Fatalf("package domain must not import other internal packages, found: %s", path)
		}
	}
}
