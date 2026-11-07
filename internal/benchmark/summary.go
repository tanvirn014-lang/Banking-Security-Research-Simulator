package benchmark

import (
	"math"
	"sort"

	"banksec-lab/internal/harness"
)

// Metric names a numeric field this package can summarize, matching
// harness's own Evidence key naming convention where one already exists
// (harness.EvidenceTimeToCompromiseMS etc.) and defining the two
// always-present Result fields (ExecutionTimeMS, Attempts) that have no
// Evidence-key constant of their own since they are never optional.
type Metric string

const (
	MetricExecutionTimeMS    Metric = "execution_time_ms"
	MetricTimeToCompromiseMS Metric = harness.EvidenceTimeToCompromiseMS
	MetricDataLeakedBytes    Metric = harness.EvidenceDataLeakedBytes
	MetricRecordsCompromised Metric = harness.EvidenceRecordsCompromised
	MetricDetectionLatencyMS Metric = harness.EvidenceDetectionLatencyMS
	MetricAttempts           Metric = "attempts"
	MetricComputationalCost  Metric = harness.EvidenceComputationalCost
	MetricMemoryUsageBytes   Metric = harness.EvidenceMemoryUsageBytes
)

// allMetrics is every metric Summarize considers -- Seed is deliberately
// excluded: it is an experiment PARAMETER (a reproducibility input),
// never an outcome to average.
var allMetrics = []Metric{
	MetricExecutionTimeMS,
	MetricTimeToCompromiseMS,
	MetricDataLeakedBytes,
	MetricRecordsCompromised,
	MetricDetectionLatencyMS,
	MetricAttempts,
	MetricComputationalCost,
	MetricMemoryUsageBytes,
}

// Summary's map keys are the typed Metric (not a bare string, as the
// plan's own struct literal showed) -- a minor, low-risk deviation for
// compile-time safety against a typo'd metric name; Metric's underlying
// type is still string, so every exported Metric constant prints and
// compares exactly as the plan's bare string would have.
//
// Summary aggregates one (ScenarioID, Mode) pair's raw runs per
// BENCHMARK_METHODOLOGY.md §4: mean, median, standard deviation (v1
// scope -- population stddev, no outlier rejection, no confidence
// intervals, per §5's deliberate YAGNI scoping) for each metric, plus
// SuccessRate.
//
// SampleSize is a disclosed addition beyond the plan's own struct
// (task-46-49-brief.md): per the user's explicit "never fabricate
// missing measurements" / "distinguish actual measurements from
// theoretical values" requirements, a metric absent from some runs
// (e.g. TimeToCompromiseMS is nil whenever a tamper was detected) has
// its Mean/Median/StdDev computed ONLY over the runs where it was
// actually present -- SampleSize records how many of this group's runs
// that is, so the output is independently analyzable without guessing
// whether an aggregate covers every run or only some. A metric present
// in ZERO runs for a group is omitted entirely from Mean/Median/StdDev/
// SampleSize -- never recorded as a fabricated 0.
//
// N and Errors are a second disclosed addition (security review finding
// I2): N is the TOTAL number of raw runs in this group, including ones
// whose RunErr != nil; Errors is how many of those errored. An earlier
// version of this code folded errored runs' (mostly zero-valued,
// infrastructure-failure, not attack-outcome) harness.Result straight
// into Mean/Median/StdDev/SuccessRate -- a run that never actually
// executed the attack would silently pull down Mean ExecutionTimeMS,
// pull down Mean Attempts, and count as a "defended" (Success==false)
// run in SuccessRate, biasing every statistic with data that was never a
// real measurement. SuccessRate and every metric below are now computed
// ONLY over this group's non-errored runs (N-Errors of them); Errors
// makes the exclusion visible rather than silently lowering N without
// explanation.
type Summary struct {
	ScenarioID  string
	Mode        string
	N           int
	Errors      int
	Mean        map[Metric]float64
	Median      map[Metric]float64
	StdDev      map[Metric]float64
	SampleSize  map[Metric]int
	SuccessRate float64
}

type groupKey struct {
	scenarioID string
	mode       string
}

// Summarize computes one Summary per (ScenarioID, Mode) pair present in
// raw, in first-seen order -- never choosing a subset of raw after
// seeing results (BENCHMARK_METHODOLOGY.md §2 step 7: "never from a
// subset chosen after seeing results"). Grouped by each RawRun's OWN
// ScenarioID/Mode labels, not harness.Result's AttackID/
// TargetConfiguration (security review findings I2/I3 -- see RawRun's
// own doc comment on why those can be empty, zero-valued, or collide
// across modes).
func Summarize(raw RawResults) []Summary {
	var order []groupKey
	groups := make(map[groupKey][]RawRun)
	for _, run := range raw {
		key := groupKey{scenarioID: run.ScenarioID, mode: run.Mode}
		if _, seen := groups[key]; !seen {
			order = append(order, key)
		}
		groups[key] = append(groups[key], run)
	}

	summaries := make([]Summary, 0, len(order))
	for _, key := range order {
		summaries = append(summaries, summarizeGroup(key, groups[key]))
	}
	return summaries
}

func summarizeGroup(key groupKey, runs []RawRun) Summary {
	s := Summary{
		ScenarioID: key.scenarioID,
		Mode:       key.mode,
		N:          len(runs),
		Mean:       make(map[Metric]float64),
		Median:     make(map[Metric]float64),
		StdDev:     make(map[Metric]float64),
		SampleSize: make(map[Metric]int),
	}

	var completed []harness.Result
	for _, run := range runs {
		if run.RunErr != nil {
			s.Errors++
			continue
		}
		completed = append(completed, run.Result)
	}

	if len(completed) == 0 {
		// Every run in this group errored -- SuccessRate is undefined
		// (0 completed attacks to have succeeded or failed), left at its
		// zero value 0, and no metric has any available value either.
		return s
	}

	var successes int
	for _, r := range completed {
		if r.Success {
			successes++
		}
	}
	s.SuccessRate = float64(successes) / float64(len(completed))

	for _, m := range allMetrics {
		values := extractMetric(completed, m)
		if len(values) == 0 {
			continue // never present in any completed run for this group -- omit entirely, never fabricate 0
		}
		s.Mean[m] = mean(values)
		s.Median[m] = median(values)
		s.StdDev[m] = stddev(values)
		s.SampleSize[m] = len(values)
	}

	return s
}

// extractMetric returns the available (non-nil / always-present) values
// of m across results, in the SAME order as results -- never padding
// with a zero for a run where m was absent.
func extractMetric(results []harness.Result, m Metric) []float64 {
	var out []float64
	for _, r := range results {
		switch m {
		case MetricExecutionTimeMS:
			out = append(out, float64(r.ExecutionTimeMS))
		case MetricAttempts:
			out = append(out, float64(r.Attempts))
		case MetricTimeToCompromiseMS:
			if r.TimeToCompromiseMS != nil {
				out = append(out, float64(*r.TimeToCompromiseMS))
			}
		case MetricDataLeakedBytes:
			if r.DataLeakedBytes != nil {
				out = append(out, float64(*r.DataLeakedBytes))
			}
		case MetricRecordsCompromised:
			if r.RecordsCompromised != nil {
				out = append(out, float64(*r.RecordsCompromised))
			}
		case MetricDetectionLatencyMS:
			if r.DetectionLatencyMS != nil {
				out = append(out, float64(*r.DetectionLatencyMS))
			}
		case MetricComputationalCost:
			if r.ComputationalCost != nil {
				out = append(out, float64(*r.ComputationalCost))
			}
		case MetricMemoryUsageBytes:
			if r.MemoryUsageBytes != nil {
				out = append(out, float64(*r.MemoryUsageBytes))
			}
		}
	}
	return out
}

func mean(values []float64) float64 {
	var sum float64
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func median(values []float64) float64 {
	sorted := append([]float64(nil), values...)
	sort.Float64s(sorted)
	n := len(sorted)
	if n%2 == 1 {
		return sorted[n/2]
	}
	return (sorted[n/2-1] + sorted[n/2]) / 2
}

// stddev is the POPULATION standard deviation (divides by N, not N-1) --
// v1 scope treats the N raw runs as the complete population being
// summarized, not a sample estimating some larger population (consistent
// with BENCHMARK_METHODOLOGY.md §4/§5's "no confidence intervals" v1
// scoping -- that distinction only matters once inferential statistics
// are in scope, which is explicitly deferred).
//
// All of mean/median/stddev are computed in float64 (security review
// finding M9): for metric values in the ordinary range this package's
// own metrics occupy (milliseconds, bytes, attempt counts), this is
// exact or effectively exact; it loses sub-integer precision only for
// values approaching float64's ~2^53 exact-integer limit, which is far
// outside any real measurement this package records.
func stddev(values []float64) float64 {
	m := mean(values)
	var sumSq float64
	for _, v := range values {
		d := v - m
		sumSq += d * d
	}
	return math.Sqrt(sumSq / float64(len(values)))
}
