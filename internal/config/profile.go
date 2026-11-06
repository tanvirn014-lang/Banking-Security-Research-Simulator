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

// SecurityProfile describes which security controls are enabled for a run.
type SecurityProfile struct {
	Name                     string                   `json:"name"`
	CryptoProfile            domain.CryptoProfileName `json:"crypto_profile"`
	MinAcceptedCryptoProfile domain.CryptoProfileName `json:"min_accepted_crypto_profile"`
	ProtocolAuthEnforced     bool                     `json:"protocol_auth_enforced"`
	AuthzEnforced            bool                     `json:"authz_enforced"`
	KeystoreEncryptedAtRest  bool                     `json:"keystore_encrypted_at_rest"`
	AuditHashChained         bool                     `json:"audit_hash_chained"`
	DetectionRules           []domain.DetectionRuleID `json:"detection_rules"`
}

// Load reads and decodes a SecurityProfile from a JSON file at path.
func Load(path string) (SecurityProfile, error) {
	var p SecurityProfile
	data, err := os.ReadFile(path)
	if err != nil {
		return p, fmt.Errorf("read profile %s: %w", path, err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, fmt.Errorf("decode profile %s: %w", path, err)
	}
	if !validCryptoProfiles[p.CryptoProfile] {
		return p, fmt.Errorf("profile %s: invalid crypto_profile %q", path, p.CryptoProfile)
	}
	if !validCryptoProfiles[p.MinAcceptedCryptoProfile] {
		return p, fmt.Errorf("profile %s: invalid min_accepted_crypto_profile %q", path, p.MinAcceptedCryptoProfile)
	}
	return p, nil
}
