package quantum

// SimulationLabel is the mandatory disclosure every quantum-subsystem
// output (CLI, benchmark export, documentation) must carry -- a hard
// requirement from docs/CRYPTOGRAPHY.md §5 and docs/QUANTUM_METHODOLOGY.md,
// not a style preference.
const SimulationLabel = "Classical simulation of a quantum algorithm's logic, at toy scale. Not executed on quantum hardware. Not a demonstrated attack against this system's real cryptographic keys."

// CircuitTrace records what a Shor/Grover run actually measured,
// deliberately keeping four different kinds of number separate rather
// than collapsing them into one "performance" figure (the user's
// explicit "separate classical computational measurements from
// theoretical quantum complexity" / "record oracle queries separately
// from actual CPU execution time" requirements):
//
//   - QubitsUsed / GateOperations / OracleQueries are STRUCTURAL COUNTS
//     of the simulated circuit itself (how many qubits, how many gate
//     applications, how many oracle/controlled-unitary invocations).
//     GateOperations is named for exactly what it counts -- a running
//     total of Apply* calls -- and NOT "CircuitDepth" (a security-review
//     correction, finding M1): true circuit depth is the length of the
//     longest dependency chain of gates that cannot run in parallel,
//     which this package has never computed; GateOperations is a
//     coarser, honestly-named count instead. For Shor specifically, it
//     sums across EVERY candidate-base attempt within one Shor call,
//     including ones that didn't yield a usable period -- not the gate
//     count of only the successful attempt.
//   - SimulatedCPUTimeMS is a REAL, measured wall-clock duration of
//     actually running this classical simulation on this machine. It is
//     NOT a measurement of quantum hardware performance and must never
//     be compared to one: classically simulating n qubits costs
//     O(2^n) (every gate touches the full amplitude vector), the
//     opposite of the exponential speedup a real quantum computer is
//     theorized to provide. See docs/QUANTUM_METHODOLOGY.md.
//   - TheoreticalComplexity is a fixed, human-readable STATEMENT of the
//     algorithm's known textbook asymptotic complexity on real quantum
//     hardware. It is never derived from this run's own measurements
//     (doing so would be exactly the "fabricating performance
//     improvements" the user's requirements explicitly rule out).
//   - Label is the mandatory SimulationLabel disclosure.
type CircuitTrace struct {
	QubitsUsed            int
	GateOperations        int
	OracleQueries         int
	SimulatedCPUTimeMS    int64
	TheoreticalComplexity string
	Label                 string
}
