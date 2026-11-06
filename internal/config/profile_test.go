package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"banksec-lab/internal/domain"
)

func writeTempProfile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp profile: %v", err)
	}
	return path
}

func TestSecurityProfile_UsesDomainSharedTypes(t *testing.T) {
	var p SecurityProfile
	p.CryptoProfile = domain.CryptoProfileName("standard")
	p.MinAcceptedCryptoProfile = domain.CryptoProfileName("standard")
	p.DetectionRules = []domain.DetectionRuleID{domain.DetectionRuleID("rule-1")}

	if p.CryptoProfile != domain.CryptoProfileName("standard") {
		t.Fatalf("CryptoProfile did not round-trip a domain.CryptoProfileName value")
	}
}

func TestLoad_Hardened(t *testing.T) {
	p, err := Load("../../configs/hardened.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.Name != "hardened" || !p.ProtocolAuthEnforced || !p.AuthzEnforced ||
		!p.KeystoreEncryptedAtRest || !p.AuditHashChained {
		t.Fatalf("hardened profile fields not as expected: %+v", p)
	}
}

func TestLoad_Vulnerable(t *testing.T) {
	p, err := Load("../../configs/vulnerable.json")
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if p.Name != "vulnerable" || p.ProtocolAuthEnforced || p.AuthzEnforced ||
		p.KeystoreEncryptedAtRest || p.AuditHashChained {
		t.Fatalf("vulnerable profile fields not as expected: %+v", p)
	}
}

func TestLoad_MissingFile(t *testing.T) {
	if _, err := Load("../../configs/does-not-exist.json"); err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestLoad_UnknownFieldRejected(t *testing.T) {
	path := writeTempProfile(t, `{
		"name": "hardened",
		"crypto_profile": "standard",
		"min_accepted_crypto_profile": "standard",
		"protocol_auth_enforce": true,
		"authz_enforced": true,
		"atomicity_enforced": true,
		"keystore_encrypted_at_rest": true,
		"audit_hash_chained": true,
		"detection_rules": []
	}`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for a misspelled/unknown field (protocol_auth_enforce), got none")
	}
}

func TestLoad_InvalidCryptoProfileRejected(t *testing.T) {
	path := writeTempProfile(t, `{
		"name": "hardened",
		"crypto_profile": "standrd",
		"min_accepted_crypto_profile": "standard",
		"protocol_auth_enforced": true,
		"authz_enforced": true,
		"atomicity_enforced": true,
		"keystore_encrypted_at_rest": true,
		"audit_hash_chained": true,
		"detection_rules": []
	}`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for invalid crypto_profile value \"standrd\", got none")
	}
	if !strings.Contains(err.Error(), "standrd") {
		t.Fatalf("expected error to name the invalid value, got: %v", err)
	}
}

func TestLoad_MissingEnforcementFieldRejected(t *testing.T) {
	// A profile that omits an enforcement field (here: atomicity_enforced)
	// must not silently default to false (vulnerable) -- found in
	// Milestone 3's security review, after a hardened test profile did
	// exactly this (internal/protocol's hardenedWireProfile omitted
	// AtomicityEnforced and every "hardened" protocol test silently ran
	// with atomicity off).
	path := writeTempProfile(t, `{
		"name": "hardened",
		"crypto_profile": "standard",
		"min_accepted_crypto_profile": "standard",
		"protocol_auth_enforced": true,
		"authz_enforced": true,
		"keystore_encrypted_at_rest": true,
		"audit_hash_chained": true,
		"detection_rules": []
	}`)
	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error for a profile missing atomicity_enforced, got none")
	}
	if !strings.Contains(err.Error(), "atomicity_enforced") {
		t.Fatalf("expected the error to name the missing field, got: %v", err)
	}
}
