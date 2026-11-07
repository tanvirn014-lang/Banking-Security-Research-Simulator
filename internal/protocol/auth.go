package protocol

import (
	"crypto/hmac"

	"banksec-lab/internal/crypto"
	"banksec-lab/internal/domain"
)

// computeTag produces the authentication value a Client attaches to a
// frame: a MAC for the symmetric profiles (standard, weak-educational),
// or a digital signature for pqc. pqc has no symmetric MAC of its own
// (internal/crypto's Engine.MAC returns ErrProfileNotImplemented for
// "pqc" -- see Task 20), so its authentication is asymmetric: the client
// signs with its ML-DSA private key, and the server verifies with the
// corresponding public key. This is why NewClient's key and NewServer's
// key are NOT the same bytes when profile.CryptoProfile is "pqc", unlike
// the symmetric profiles where both sides share one key.
func computeTag(e crypto.Engine, profile domain.CryptoProfileName, key, data []byte) ([]byte, error) {
	if profile == "pqc" {
		return e.Sign(profile, key, data)
	}
	return e.MAC(profile, key, data)
}

// verifyTag checks a frame's authentication value against data, using
// whichever scheme the frame's *declared* profile implies (not the
// server's own configured profile) -- the downgrade check elsewhere is
// what polices whether a weaker declared profile is acceptable at all;
// verifyTag's job is only to say whether the tag is valid for the scheme
// it claims to use.
func verifyTag(e crypto.Engine, profile domain.CryptoProfileName, key, data, tag []byte) (bool, error) {
	if profile == "pqc" {
		return e.Verify(profile, key, data, tag)
	}
	expected, err := e.MAC(profile, key, data)
	if err != nil {
		return false, err
	}
	return hmac.Equal(expected, tag), nil
}
