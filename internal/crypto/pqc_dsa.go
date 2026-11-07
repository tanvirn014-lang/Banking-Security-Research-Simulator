package crypto

import (
	"crypto/mldsa"

	"banksec-lab/internal/apperr"
)

// The "pqc" profile's Sign/Verify use ML-DSA-44 (NIST FIPS 204, via the
// Go 1.27.3 standard library's crypto/mldsa -- confirmed present via
// `go doc crypto/mldsa`, so no cloudflare/circl dependency is needed for
// this half of the pqc profile either, superseding
// IMPLEMENTATION_PLAN.md's circl fallback note). MLDSA44 is the
// parameter set the stdlib itself recommends for most applications.
//
// Signing is deterministic (SignDeterministic, not the randomized Sign)
// for the same reason the rest of this project favors determinism:
// reproducible experiments and benchmarks (ARCHITECTURE.md's
// reproducibility principle).

var mldsaParams = mldsa.MLDSA44()

func pqcDSASign(privKeySeed, msg []byte) ([]byte, error) {
	sk, err := mldsa.NewPrivateKey(mldsaParams, privKeySeed)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeValidation, "invalid ML-DSA-44 private key seed", err)
	}
	sig, err := sk.SignDeterministic(msg, &mldsa.Options{})
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "ML-DSA-44 sign", err)
	}
	return sig, nil
}

func pqcDSAVerify(pubKeyBytes, msg, sig []byte) (bool, error) {
	pk, err := mldsa.NewPublicKey(mldsaParams, pubKeyBytes)
	if err != nil {
		return false, apperr.Wrap(apperr.CodeValidation, "invalid ML-DSA-44 public key", err)
	}
	// A verification failure (wrong message/signature/key) is a normal,
	// expected outcome -- reported as ok=false, not an error -- matching
	// the standard profile's Ed25519 Verify semantics. Only a malformed
	// key (above) is an error.
	return mldsa.Verify(pk, msg, sig, &mldsa.Options{}) == nil, nil
}
