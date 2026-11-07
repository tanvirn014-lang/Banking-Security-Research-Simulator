package benchmark

import (
	"math"
	"testing"
	"time"

	"banksec-lab/internal/harness"
)

func i64(v int64) *int64 { return &v }

func rawRun(scenarioID, mode string, success bool, executionMS int64, ttc *int64) RawRun {
	return RawRun{
		ScenarioID: scenarioID,
		Mode:       mode,
		RunID:      scenarioID + "-" + mode,
		Timestamp:  time.Now(),
		Result: harness.Result{
			AttackID:            scenarioID,
			TargetConfiguration: mode,
			Success:             success,
			ExecutionTimeMS:     executionMS,
			TimeToCompromiseMS:  ttc,
			Attempts:            1,
		},
	}
}

func TestSummarize_ComputesMeanMedianStdDev(t *testing.T) {
	raw := RawResults{
		rawRun("s1", "vulnerable", true, 10, i64(100)),
		rawRun("s1", "vulnerable", true, 20, i64(200)),
		rawRun("s1", "vulnerable", true, 30, i64(300)),
	}
	summaries := Summarize(raw)
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary (one scenario/mode pair), got %d", len(summaries))
	}
	s := summaries[0]
	if s.ScenarioID != "s1" || s.Mode != "vulnerable" {
		t.Fatalf("expected ScenarioID=s1 Mode=vulnerable, got %+v", s)
	}
	if got := s.Mean[MetricExecutionTimeMS]; math.Abs(got-20) > 1e-9 {
		t.Fatalf("expected mean execution time 20, got %v", got)
	}
	if got := s.Median[MetricExecutionTimeMS]; math.Abs(got-20) > 1e-9 {
		t.Fatalf("expected median execution time 20, got %v", got)
	}
	// population stddev of {10,20,30} = sqrt(((10)^2+(0)^2+(10)^2)/3) = sqrt(200/3) ~= 8.165
	wantStdDev := math.Sqrt(200.0 / 3.0)
	if got := s.StdDev[MetricExecutionTimeMS]; math.Abs(got-wantStdDev) > 1e-6 {
		t.Fatalf("expected stddev ~%.6f, got %v", wantStdDev, got)
	}
	if got := s.Mean[MetricTimeToCompromiseMS]; math.Abs(got-200) > 1e-9 {
		t.Fatalf("expected mean time-to-compromise 200, got %v", got)
	}
	if s.SampleSize[MetricTimeToCompromiseMS] != 3 {
		t.Fatalf("expected SampleSize=3 for a metric present in every run, got %d", s.SampleSize[MetricTimeToCompromiseMS])
	}
}

func TestSummarize_SuccessRate(t *testing.T) {
	raw := RawResults{
		rawRun("s1", "vulnerable", true, 1, nil),
		rawRun("s1", "vulnerable", true, 1, nil),
		rawRun("s1", "vulnerable", false, 1, nil),
		rawRun("s1", "vulnerable", false, 1, nil),
	}
	summaries := Summarize(raw)
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	if got := summaries[0].SuccessRate; math.Abs(got-0.5) > 1e-9 {
		t.Fatalf("expected SuccessRate=0.5, got %v", got)
	}
}

// TestSummarize_AbsentMetricNeverFabricatedAsZero is the regression test
// for the user's explicit "never fabricate missing measurements" /
// "represent unavailable metrics explicitly" requirements: a metric
// present in only SOME of a group's runs (e.g. TimeToCompromiseMS is
// nil whenever a tamper was detected) must be averaged over ONLY the
// runs where it was actually present, and a metric present in NONE of
// the runs must be omitted entirely -- never silently treated as 0.
func TestSummarize_AbsentMetricNeverFabricatedAsZero(t *testing.T) {
	raw := RawResults{
		rawRun("s1", "hardened", false, 5, nil),     // detected: no TimeToCompromiseMS
		rawRun("s1", "hardened", false, 5, nil),     // detected: no TimeToCompromiseMS
		rawRun("s1", "hardened", true, 5, i64(999)), // one undetected run
	}
	summaries := Summarize(raw)
	s := summaries[0]

	if got := s.Mean[MetricTimeToCompromiseMS]; got != 999 {
		t.Fatalf("expected the mean to be computed over ONLY the 1 run where TimeToCompromiseMS was present (999), got %v", got)
	}
	if s.SampleSize[MetricTimeToCompromiseMS] != 1 {
		t.Fatalf("expected SampleSize=1 for TimeToCompromiseMS (only 1 of 3 runs had it), got %d", s.SampleSize[MetricTimeToCompromiseMS])
	}

	// DataLeakedBytes was never present in ANY run for this group --
	// must be omitted entirely, not recorded as 0.
	if _, ok := s.Mean[MetricDataLeakedBytes]; ok {
		t.Fatalf("expected DataLeakedBytes to be entirely ABSENT from Mean (never present in any run), got %v", s.Mean[MetricDataLeakedBytes])
	}
	if _, ok := s.SampleSize[MetricDataLeakedBytes]; ok {
		t.Fatalf("expected DataLeakedBytes to be entirely ABSENT from SampleSize, got %v", s.SampleSize[MetricDataLeakedBytes])
	}
}

func TestSummarize_SeparatesScenarioAndModePairs(t *testing.T) {
	raw := RawResults{
		rawRun("s1", "vulnerable", true, 10, nil),
		rawRun("s1", "hardened", false, 10, nil),
		rawRun("s2", "vulnerable", true, 10, nil),
	}
	summaries := Summarize(raw)
	if len(summaries) != 3 {
		t.Fatalf("expected 3 distinct (scenario,mode) summaries, got %d: %+v", len(summaries), summaries)
	}
}

func TestSummarize_EmptyInputReturnsNoSummaries(t *testing.T) {
	if s := Summarize(nil); len(s) != 0 {
		t.Fatalf("expected no summaries for empty input, got %+v", s)
	}
}

// TestSummarize_ExcludesErroredRunsFromStatsAndTracksThemSeparately is
// the regression test for security review finding I2: an earlier
// version of Summarize folded a run whose RunErr != nil straight into
// Mean/Median/StdDev/SuccessRate using its (mostly zero-valued,
// infrastructure-failure, not attack-outcome) harness.Result -- a run
// that never actually executed the attack silently pulled down the mean
// and counted as a "defended" (Success==false) run.
func TestSummarize_ExcludesErroredRunsFromStatsAndTracksThemSeparately(t *testing.T) {
	errored := rawRun("s1", "vulnerable", false, 0, nil)
	errored.RunErr = errTestSentinel
	raw := RawResults{
		rawRun("s1", "vulnerable", true, 300, nil),
		rawRun("s1", "vulnerable", true, 300, nil),
		errored,
	}
	summaries := Summarize(raw)
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	s := summaries[0]
	if s.N != 3 {
		t.Fatalf("expected N=3 (total raw runs in this group, including the errored one), got %d", s.N)
	}
	if s.Errors != 1 {
		t.Fatalf("expected Errors=1, got %d", s.Errors)
	}
	if s.SuccessRate != 1.0 {
		t.Fatalf("expected SuccessRate=1.0 (computed over the 2 COMPLETED runs only, both successful), got %v", s.SuccessRate)
	}
	if got := s.Mean[MetricExecutionTimeMS]; got != 300 {
		t.Fatalf("expected mean execution time 300 (the errored run's 0 must NOT pull this down), got %v", got)
	}
	if got := s.SampleSize[MetricExecutionTimeMS]; got != 2 {
		t.Fatalf("expected SampleSize=2 for execution time (only the 2 completed runs), got %d", got)
	}
}

// TestSummarize_AllRunsErroredGroup is the degenerate case: a group
// where every run errored has no meaningful SuccessRate or metrics at
// all -- SuccessRate stays at its zero value 0, and no metric gets a
// SampleSize entry, rather than dividing by zero or fabricating data
// from nothing.
func TestSummarize_AllRunsErroredGroup(t *testing.T) {
	r1 := rawRun("s1", "vulnerable", false, 0, nil)
	r1.RunErr = errTestSentinel
	r2 := rawRun("s1", "vulnerable", false, 0, nil)
	r2.RunErr = errTestSentinel
	raw := RawResults{r1, r2}

	summaries := Summarize(raw)
	s := summaries[0]
	if s.N != 2 || s.Errors != 2 {
		t.Fatalf("expected N=2 Errors=2, got N=%d Errors=%d", s.N, s.Errors)
	}
	if s.SuccessRate != 0 {
		t.Fatalf("expected SuccessRate=0 (undefined, no completed runs) rather than a NaN or fabricated value, got %v", s.SuccessRate)
	}
	if len(s.SampleSize) != 0 {
		t.Fatalf("expected no metric to have a SampleSize entry when every run in the group errored, got %+v", s.SampleSize)
	}
}
