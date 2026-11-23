// Copyright IBM Corp. 2019, 2026
// SPDX-License-Identifier: MPL-2.0

package ociauth

import (
	"strings"
	"testing"
)

// TestCLIHandler_Help verifies that Help uses BinaryName in the commands it
// shows and falls back to "vault" when it's unset.
func TestCLIHandler_Help(t *testing.T) {
	t.Parallel()

	if help := (&CLIHandler{}).Help(); !strings.Contains(help, "vault login -method=oci") {
		t.Fatalf("expected help to use vault, got:\n%s", help)
	}

	help := (&CLIHandler{BinaryName: "vault-client"}).Help()
	if !strings.Contains(help, "vault-client login -method=oci") || strings.Contains(help, "vault login") {
		t.Fatalf("expected help to use vault-client, got:\n%s", help)
	}
}
