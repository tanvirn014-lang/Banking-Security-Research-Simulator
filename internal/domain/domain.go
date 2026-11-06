// Package domain holds the value types shared across BankSec Lab's
// packages (ledger, keystore, backend, protocol, audit, harness, ...), so
// that no package needs to import another solely to reuse its types.
package domain

// AccountID identifies a synthetic bank account.
type AccountID string

// TransactionID identifies one balanced set of ledger entries.
type TransactionID string

// Money is a minor-unit (cents) amount. Debits are negative, credits are
// positive in ledger entries; never represented as a float.
type Money int64

// PrincipalID identifies a simulated actor (account owner or operator).
type PrincipalID string

// Role distinguishes what a Principal is permitted to do.
type Role string

const (
	RoleAccountOwner       Role = "account-owner"
	RolePrivilegedOperator Role = "privileged-operator"
)

// Principal is the actor performing an operation.
type Principal struct {
	ID   PrincipalID
	Role Role
}

// CryptoProfileName selects which cryptographic profile is in effect:
// "weak-educational", "standard", or "pqc".
type CryptoProfileName string

// DetectionRuleID identifies one Detection Engine rule.
type DetectionRuleID string
