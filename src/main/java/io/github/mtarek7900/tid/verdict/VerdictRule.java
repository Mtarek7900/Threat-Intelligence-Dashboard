package io.github.mtarek7900.tid.verdict;

import io.github.mtarek7900.tid.source.Outcome;
import io.github.mtarek7900.tid.source.SourceResult;
import io.github.mtarek7900.tid.source.VirusTotalFacts;
import java.util.List;

/**
 * Combines a Lookup's Source Results into a Verdict: the worst Signal wins; with no Signal it's
 * Clean if any Source has Seen the Indicator, otherwise Unknown.
 */
public final class VerdictRule {

    private final VerdictThresholds thresholds;

    public VerdictRule(VerdictThresholds thresholds) {
        this.thresholds = thresholds;
    }

    public Decision decide(List<SourceResult> results) {
        var readings = results.stream().map(this::read).toList();
        return new Decision(verdictOf(readings), readings);
    }

    private static Verdict verdictOf(List<Reading> readings) {
        if (readings.stream().anyMatch(reading -> reading.signal() == Signal.MALICIOUS)) {
            return Verdict.MALICIOUS;
        }
        if (readings.stream().anyMatch(reading -> reading.signal() == Signal.SUSPICIOUS)) {
            return Verdict.SUSPICIOUS;
        }
        if (readings.stream().anyMatch(reading -> reading.result().outcome() == Outcome.SEEN)) {
            return Verdict.CLEAN;
        }
        return Verdict.UNKNOWN;
    }

    private Reading read(SourceResult result) {
        if (result.outcome() == Outcome.NOT_SEEN) {
            return new Reading(result, Signal.NONE, result.source() + " has no record of it. No Signal.");
        }
        return switch (result.facts()) {
            case VirusTotalFacts facts -> read(result, facts, thresholds.virustotal());
        };
    }

    private static Reading read(SourceResult result, VirusTotalFacts facts, VerdictThresholds.VirusTotal thresholds) {
        var flagged = "%s: %d of %d engines flagged it. "
                .formatted(result.source(), facts.enginesFlagged(), facts.enginesTotal());
        if (facts.enginesFlagged() >= thresholds.maliciousEngines()) {
            return new Reading(
                    result, Signal.MALICIOUS, flagged + thresholds.maliciousEngines() + " or more is Malicious.");
        }
        if (facts.enginesFlagged() >= thresholds.suspiciousEngines()) {
            return new Reading(result, Signal.SUSPICIOUS, flagged + range(thresholds) + " is Suspicious.");
        }
        return new Reading(result, Signal.NONE, flagged + "No Signal.");
    }

    private static String range(VerdictThresholds.VirusTotal thresholds) {
        var highest = thresholds.maliciousEngines() - 1;
        return thresholds.suspiciousEngines() == highest
                ? String.valueOf(highest)
                : thresholds.suspiciousEngines() + " to " + highest;
    }
}
