package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"banksec-lab/internal/domain"
)

var validCryptoProfiles = map[domain.CryptoProfileName]bool{
	"weak-educational": true,
	"standard":         true,
	"pqc":              true,
}

// cryptoProfileRank gives crypto profiles the same comparable strength
// ordering internal/protocol's profileRank uses, duplicated here because
// internal/protocol imports this package (a shared helper would cycle).
func cryptoProfileRank(name domain.CryptoProfileName) int {
	switch name {
	case "weak-educational":
		return 0
	case "standard":
		return 1
	case "pqc":
		return 2
	default:
		return -1
	}
}

// SecurityProfile describes which security controls are enabled for a run.
type SecurityProfile struct {
	Name                     string                   `json:"name"`
	CryptoProfile            domain.CryptoProfileName `json:"crypto_profile"`
	MinAcceptedCryptoProfile domain.CryptoProfileName `json:"min_accepted_crypto_profile"`
	ProtocolAuthEnforced     bool                     `json:"protocol_auth_enforced"`
	AuthzEnforced            bool                     `json:"authz_enforced"`
	// AtomicityEnforced gates whether Transfer's balance-check-then-append
	// sequence is a single serializing unit. False (vulnerable) opens a
	// deliberate, deterministic TOCTOU window -- see internal/backend's
	// concurrency_test.go and service.go.
	AtomicityEnforced       bool                     `json:"atomicity_enforced"`
	KeystoreEncryptedAtRest bool                     `json:"keystore_encrypted_at_rest"`
	AuditHashChained        bool                     `json:"audit_hash_chained"`
	DetectionRules          []domain.DetectionRuleID `json:"detection_rules"`
}

// securityProfileRaw mirrors SecurityProfile but with the enforcement
// booleans as pointers, so Load can tell "explicitly false" apart from
// "absent from the file" -- a missing field must never silently default
// to false (vulnerable). Found necessary in Milestone 3's security
// review, after a hardened test profile omitted one such field and every
// "hardened" test built from it silently ran with that control off.
type securityProfileRaw struct {
	Name                     string                   `json:"name"`
	CryptoProfile            domain.CryptoProfileName `json:"crypto_profile"`
	MinAcceptedCryptoProfile domain.CryptoProfileName `json:"min_accepted_crypto_profile"`
	ProtocolAuthEnforced     *bool                    `json:"protocol_auth_enforced"`
	AuthzEnforced            *bool                    `json:"authz_enforced"`
	AtomicityEnforced        *bool                    `json:"atomicity_enforced"`
	KeystoreEncryptedAtRest  *bool                    `json:"keystore_encrypted_at_rest"`
	AuditHashChained         *bool                    `json:"audit_hash_chained"`
	DetectionRules           []domain.DetectionRuleID `json:"detection_rules"`
}

// requiredBoolFields names, in JSON key form, every enforcement field
// that must be explicitly present (true or false) in a profile file.
var requiredBoolFields = []struct {
	name string
	ptr  func(*securityProfileRaw) *bool
}{
	{"protocol_auth_enforced", func(r *securityProfileRaw) *bool { return r.ProtocolAuthEnforced }},
	{"authz_enforced", func(r *securityProfileRaw) *bool { return r.AuthzEnforced }},
	{"atomicity_enforced", func(r *securityProfileRaw) *bool { return r.AtomicityEnforced }},
	{"keystore_encrypted_at_rest", func(r *securityProfileRaw) *bool { return r.KeystoreEncryptedAtRest }},
	{"audit_hash_chained", func(r *securityProfileRaw) *bool { return r.AuditHashChained }},
}

// Load reads and decodes a SecurityProfile from a JSON file at path.
func Load(path string) (SecurityProfile, error) {
	var empty SecurityProfile
	data, err := os.ReadFile(path)
	if err != nil {
		return empty, fmt.Errorf("read profile %s: %w", path, err)
	}

	var raw securityProfileRaw
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&raw); err != nil {
		return empty, fmt.Errorf("decode profile %s: %w", path, err)
	}

	for _, f := range requiredBoolFields {
		if f.ptr(&raw) == nil {
			return empty, fmt.Errorf("profile %s: missing required field %q", path, f.name)
		}
	}

	if !validCryptoProfiles[raw.CryptoProfile] {
		return empty, fmt.Errorf("profile %s: invalid crypto_profile %q", path, raw.CryptoProfile)
	}
	if !validCryptoProfiles[raw.MinAcceptedCryptoProfile] {
		return empty, fmt.Errorf("profile %s: invalid min_accepted_crypto_profile %q", path, raw.MinAcceptedCryptoProfile)
	}
	if cryptoProfileRank(raw.CryptoProfile) < cryptoProfileRank(raw.MinAcceptedCryptoProfile) {
		return empty, fmt.Errorf("profile %s: crypto_profile %q ranks below min_accepted_crypto_profile %q -- this server could never authenticate its own client's traffic",
			path, raw.CryptoProfile, raw.MinAcceptedCryptoProfile)
	}

	return SecurityProfile{
		Name:                     raw.Name,
		CryptoProfile:            raw.CryptoProfile,
		MinAcceptedCryptoProfile: raw.MinAcceptedCryptoProfile,
		ProtocolAuthEnforced:     *raw.ProtocolAuthEnforced,
		AuthzEnforced:            *raw.AuthzEnforced,
		AtomicityEnforced:        *raw.AtomicityEnforced,
		KeystoreEncryptedAtRest:  *raw.KeystoreEncryptedAtRest,
		AuditHashChained:         *raw.AuditHashChained,
		DetectionRules:           raw.DetectionRules,
	}, nil
}
