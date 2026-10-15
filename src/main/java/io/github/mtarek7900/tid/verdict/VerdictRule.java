package io.github.mtarek7900.tid.verdict;

import io.github.mtarek7900.tid.source.AbuseIpdbFacts;
import io.github.mtarek7900.tid.source.NotCheckedReason;
import io.github.mtarek7900.tid.source.OtxFacts;
import io.github.mtarek7900.tid.source.Outcome;
import io.github.mtarek7900.tid.source.SourceResult;
import io.github.mtarek7900.tid.source.VirusTotalFacts;
import java.util.List;

/**
 * Combines a Lookup's Source Results into a Verdict: the worst counted Signal wins; with no counted
 * Signal it's Clean if any Source has Seen the Indicator, otherwise Unknown. A Corroborating
 * Source's Signal counts only when another Source also gives one. It's a Partial Verdict if any
 * Source was Not Checked.
 */
public final class VerdictRule {

    private final VerdictThresholds thresholds;

    public VerdictRule(VerdictThresholds thresholds) {
        this.thresholds = thresholds;
    }

    public Decision decide(List<SourceResult> results) {
        var anotherSignal = results.stream()
                .filter(result -> !corroborating(result))
                .anyMatch(result -> read(result, false).signal() != Signal.NONE);
        var readings = results.stream().map(result -> read(result, anotherSignal)).toList();
        var notChecked = results.stream()
                .filter(result -> result.outcome() == Outcome.NOT_CHECKED)
                .map(SourceResult::source)
                .toList();
        return new Decision(verdictOf(readings), readings, notChecked);
    }

    private static boolean corroborating(SourceResult result) {
        return result.facts() != null && result.facts().fromCorroboratingSource();
    }

    private static Verdict verdictOf(List<Reading> readings) {
        var counted = readings.stream().filter(Reading::counted).map(Reading::signal).toList();
        if (counted.contains(Signal.MALICIOUS)) {
            return Verdict.MALICIOUS;
        }
        if (counted.contains(Signal.SUSPICIOUS)) {
            return Verdict.SUSPICIOUS;
        }
        if (readings.stream().anyMatch(reading -> reading.result().outcome() == Outcome.SEEN)) {
            return Verdict.CLEAN;
        }
        return Verdict.UNKNOWN;
    }

    /** @param anotherSignal whether a Source that isn't a Corroborating Source gave a Signal */
    private Reading read(SourceResult result, boolean anotherSignal) {
        switch (result.outcome()) {
            case NOT_SEEN -> {
                return Reading.counted(result, Signal.NONE, result.source() + " has no record of it. No Signal.");
            }
            case NOT_CHECKED -> {
                return Reading.counted(
                        result,
                        Signal.NONE,
                        result.source() + " was Not Checked: " + because(result.notCheckedReason()) + ".");
            }
            case SEEN -> {}
        }
        return switch (result.facts()) {
            case VirusTotalFacts facts -> read(result, facts, thresholds.virustotal());
            case AbuseIpdbFacts facts -> read(result, facts, thresholds.abuseipdb());
            case OtxFacts facts -> read(result, facts, anotherSignal);
        };
    }

    private static Reading read(SourceResult result, VirusTotalFacts facts, VerdictThresholds.VirusTotal thresholds) {
        var flagged = "%s: %d of %d engines flagged it. "
                .formatted(result.source(), facts.enginesFlagged(), facts.enginesTotal());
        if (facts.enginesFlagged() >= thresholds.maliciousEngines()) {
            return Reading.counted(
                    result, Signal.MALICIOUS, flagged + thresholds.maliciousEngines() + " or more is Malicious.");
        }
        if (facts.enginesFlagged() >= thresholds.suspiciousEngines()) {
            return Reading.counted(
                    result,
                    Signal.SUSPICIOUS,
                    flagged + range(thresholds.suspiciousEngines(), thresholds.maliciousEngines(), "")
                            + " is Suspicious.");
        }
        return Reading.counted(result, Signal.NONE, flagged + "No Signal.");
    }

    private static Reading read(SourceResult result, AbuseIpdbFacts facts, VerdictThresholds.AbuseIpdb thresholds) {
        var confidence = "%s: abuse confidence %d%%. ".formatted(result.source(), facts.abuseConfidence());
        if (facts.abuseConfidence() >= thresholds.maliciousConfidence()) {
            return Reading.counted(
                    result, Signal.MALICIOUS, confidence + thresholds.maliciousConfidence() + "% or more is Malicious.");
        }
        if (facts.abuseConfidence() >= thresholds.suspiciousConfidence()) {
            return Reading.counted(
                    result,
                    Signal.SUSPICIOUS,
                    confidence + range(thresholds.suspiciousConfidence(), thresholds.maliciousConfidence(), "%")
                            + " is Suspicious.");
        }
        return Reading.counted(result, Signal.NONE, confidence + "No Signal.");
    }

    private static Reading read(SourceResult result, OtxFacts facts, boolean anotherSignal) {
        var pulses = "%s: in %d %s. Suspicious, "
                .formatted(result.source(), facts.pulseCount(), facts.pulseCount() == 1 ? "pulse" : "pulses");
        if (anotherSignal) {
            return Reading.counted(
                    result, Signal.SUSPICIOUS, pulses + "counted because another Source also gave a Signal.");
        }
        return new Reading(
                result,
                Signal.SUSPICIOUS,
                false,
                pulses + "but not counted: " + result.source()
                        + " is a Corroborating Source and no other Source gave a Signal.");
    }

    private static String because(NotCheckedReason reason) {
        return switch (reason) {
            case TIMEOUT -> "it didn't answer in time";
            case SOURCE_ERROR -> "it answered with an error";
            case RATE_LIMITED -> "it is limiting how often it can be asked";
            case MISSING_API_KEY -> "no API key is configured";
        };
    }

    /** The values that give a Suspicious Signal: from its threshold up to just below Malicious. */
    private static String range(int suspicious, int malicious, String unit) {
        var highest = malicious - 1;
        return suspicious == highest
                ? highest + unit
                : suspicious + unit + " to " + highest + unit;
    }
}
