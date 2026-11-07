package quantum

import "math"

// ApplyQFT applies the quantum Fourier transform to the sub-register
// named by qubits (qubits[0] is bit 0 / least-significant of the
// register's conceptual integer value, matching Circuit's own index
// convention), built entirely from the elementary ApplyH and
// ApplyControlledPhase gates (plus a final qubit-order reversal via
// SWAP, itself three CNOTs) -- genuinely elementary-gate-decomposed, no
// oracle-level shortcut. When qubits spans the Circuit's entire
// register, ApplyQFT computes exactly the textbook DFT matrix on
// State -- see TestApplyQFT_MatchesTextbookDFTMatrix, which checks this
// directly against a brute-force reference DFT.
//
// This is the quantum phase estimation subroutine Shor's order-finding
// (shor.go) uses on the counting register, and is standard, independent
// of this package's own internal/quantum-specific additions
// (ApplyPermutationUnitary et al.) -- see docs/QUANTUM_METHODOLOGY.md
// for how this fits into what's elementary-gate-decomposed vs.
// oracle-level in this simulator.
func ApplyQFT(c *Circuit, qubits []int) {
	n := len(qubits)
	for i := n - 1; i >= 0; i-- {
		c.ApplyH(qubits[i])
		for j := i - 1; j >= 0; j-- {
			angle := 2 * math.Pi / float64(int64(1)<<uint(i-j+1))
			c.ApplyControlledPhase(qubits[j], qubits[i], angle)
		}
	}
	reverseQubitOrder(c, qubits)
}

// ApplyInverseQFT applies the exact inverse of ApplyQFT -- the precise
// reverse-chronological, angle-negated replay of ApplyQFT's own gate
// sequence (H is self-inverse, ApplyControlledPhase(theta)'s inverse is
// ApplyControlledPhase(-theta), and the final SWAP-based reversal is
// self-inverse). This is the quantum part of Shor's algorithm that
// actually extracts the period estimate: measuring the counting
// register immediately after ApplyInverseQFT.
func ApplyInverseQFT(c *Circuit, qubits []int) {
	reverseQubitOrder(c, qubits)
	n := len(qubits)
	for i := 0; i < n; i++ {
		for j := 0; j < i; j++ {
			angle := -2 * math.Pi / float64(int64(1)<<uint(i-j+1))
			c.ApplyControlledPhase(qubits[j], qubits[i], angle)
		}
		c.ApplyH(qubits[i])
	}
}

func reverseQubitOrder(c *Circuit, qubits []int) {
	n := len(qubits)
	for i := 0; i < n/2; i++ {
		swapQubits(c, qubits[i], qubits[n-1-i])
	}
}

// swapQubits exchanges two qubits' values via the standard three-CNOT
// SWAP decomposition -- an elementary-gate construction, not a direct
// index permutation shortcut.
func swapQubits(c *Circuit, a, b int) {
	if a == b {
		return
	}
	c.ApplyCNOT(a, b)
	c.ApplyCNOT(b, a)
	c.ApplyCNOT(a, b)
}
