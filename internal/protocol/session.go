package protocol

import (
	"crypto/hkdf"
	"crypto/sha256"
	"fmt"

	"banksec-lab/internal/config"
	"banksec-lab/internal/crypto"
	"banksec-lab/internal/domain"
)

// handshakeSeq is the sequence number reserved for the key-agreement
// exchange. Ordinary request frames start at 1 (pipeClient.nextSeq is
// pre-incremented), so 0 is free and unambiguous.
//
// A handshake frame is recognised and consumed before the replay check
// ever sees it, which matters: that check rejects any frame whose
// sequence number is not strictly greater than the last seen, and
// lastSeen starts at 0, so a handshake routed through it would be
// rejected as a replay of itself.
const handshakeSeq uint64 = 0

// sessionKeyLen is the derived session key's size in bytes -- 32, for
// AES-256 under the standard profile's AES-GCM and the weak-educational
// profile's AES-ECB alike.
const sessionKeyLen = 32

// sessionKeyInfo is the HKDF info string. It exists for domain
// separation: the same shared secret must never produce the same bytes
// for two different purposes, and a labelled derivation is what
// guarantees that if this protocol later derives a second key.
const sessionKeyInfo = "banksec-lab/protocol/session-encryption/v1"

// supportsWireEncryption reports whether a cryptographic profile has
// key agreement of the shape this protocol's handshake needs.
//
// standard uses X25519 and weak-educational a small-group
// Diffie-Hellman, both of which fit Engine.DeriveSharedSecret. pqc does
// not: its key establishment is ML-KEM encapsulation, a two-message
// asymmetric shape that this generate-then-exchange handshake cannot
// express. Frames under pqc are therefore authenticated but not
// encrypted, which is stated rather than papered over -- see
// docs/CRYPTOGRAPHY.md.
func supportsWireEncryption(profile domain.CryptoProfileName) bool {
	switch profile {
	case "standard", "weak-educational":
		return true
	default:
		return false
	}
}

// wireEncryptionEnabled reports whether a connection under this security
// profile encrypts its frames.
//
// Gated on ProtocolAuthEnforced, the same flag that gates replay, tamper
// and downgrade checking, because wire confidentiality is a protocol
// protection and belongs with the others. Two consequences follow, and
// both are deliberate.
//
// The weakened profile keeps its exploitable tamper surface. Encrypting
// its traffic would have closed that surface by accident -- AES-GCM
// authenticates its own ciphertext, so a tampered frame would be caught
// during decryption even with every explicit check disabled, silently
// removing an attack the corpus depends on. A security control that
// quietly strengthens the configuration built to be weak makes the
// comparison between them meaningless.
//
// And it yields the property this exists to demonstrate: under the
// hardened profile banking traffic is ciphertext on the wire, and under
// the weakened one it is readable JSON.
func wireEncryptionEnabled(profile config.SecurityProfile) bool {
	return profile.ProtocolAuthEnforced && supportsWireEncryption(profile.CryptoProfile)
}

// deriveSessionKey turns an agreed shared secret into the symmetric key
// the connection encrypts its frames under.
//
// The raw secret is never used directly. Under weak-educational it is a
// small-group Diffie-Hellman result -- only a few bytes, and far too
// small to serve as an AES key at all -- so a derivation step is not
// optional there. Under standard it is a 32-byte X25519 output that
// could technically be used raw, but deriving both uniformly means the
// two profiles differ only in the strength of the agreement, which is
// exactly the property the attack scenarios exist to measure.
//
// HKDF-Expand with a labelled info string gives that derivation and the
// domain separation described on sessionKeyInfo.
func deriveSessionKey(e crypto.Engine, profile domain.CryptoProfileName, privateKey, peerPublicKey []byte) ([]byte, error) {
	secret, err := e.DeriveSharedSecret(profile, privateKey, peerPublicKey)
	if err != nil {
		return nil, fmt.Errorf("agree session secret: %w", err)
	}
	if len(secret) == 0 {
		return nil, fmt.Errorf("agreed session secret is empty")
	}

	key, err := hkdf.Key(sha256.New, secret, nil, sessionKeyInfo, sessionKeyLen)
	if err != nil {
		return nil, fmt.Errorf("derive session key: %w", err)
	}
	return key, nil
}

// sealPayload encrypts a request payload under the session key, when
// the connection has one.
//
// Encryption happens before the authentication tag is computed, so the
// tag covers the ciphertext: encrypt-then-MAC. The alternatives --
// MAC-then-encrypt and encrypt-and-MAC -- have well-known weaknesses,
// and the ordering is the only thing that distinguishes them, so it is
// worth stating plainly that this is the deliberate one.
//
// A nil session key means this connection has no wire encryption (pqc,
// or a handshake that has not happened), and the payload passes through
// unchanged.
func sealPayload(e crypto.Engine, profile domain.CryptoProfileName, sessionKey, plaintext []byte) ([]byte, error) {
	if sessionKey == nil {
		return plaintext, nil
	}
	ct, err := e.Encrypt(profile, sessionKey, plaintext)
	if err != nil {
		return nil, fmt.Errorf("encrypt frame payload: %w", err)
	}
	return ct, nil
}

// openPayload decrypts a frame payload. Callers must verify the frame's
// authentication tag first: this is the "then-MAC" half of
// encrypt-then-MAC, and decrypting unauthenticated bytes would throw
// that ordering away.
//
// A decryption failure is an error, never a fallback to treating the
// bytes as plaintext. Falling back would mean an attacker who corrupts
// the ciphertext gets their bytes handed to the request parser.
func openPayload(e crypto.Engine, profile domain.CryptoProfileName, sessionKey, payload []byte) ([]byte, error) {
	if sessionKey == nil {
		return payload, nil
	}
	pt, err := e.Decrypt(profile, sessionKey, payload)
	if err != nil {
		return nil, fmt.Errorf("decrypt frame payload: %w", err)
	}
	return pt, nil
}

// cryptoName is a small helper for tests and callers holding a profile
// name as a plain string.
func cryptoName(s string) domain.CryptoProfileName { return domain.CryptoProfileName(s) }

// SessionKeyFromSecret derives the frame-encryption key from an already
// agreed shared secret, exactly as a connection does.
//
// Exported because the derivation is not a secret: HKDF with a published
// info string is public knowledge, and only the shared secret itself is
// private. An attacker who recovers that secret -- by solving the small
// group's discrete logarithm, say -- can derive the session key without
// any help from this package, so exposing the step lets an attack
// scenario demonstrate the real consequence rather than reimplement a
// detail it could trivially have copied.
func SessionKeyFromSecret(secret []byte) ([]byte, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("session secret is empty")
	}
	key, err := hkdf.Key(sha256.New, secret, nil, sessionKeyInfo, sessionKeyLen)
	if err != nil {
		return nil, fmt.Errorf("derive session key: %w", err)
	}
	return key, nil
}
