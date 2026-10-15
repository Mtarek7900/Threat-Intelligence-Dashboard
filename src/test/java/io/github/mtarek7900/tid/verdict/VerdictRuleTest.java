package io.github.mtarek7900.tid.verdict;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import io.github.mtarek7900.tid.indicator.Indicator;
import io.github.mtarek7900.tid.indicator.IndicatorType;
import io.github.mtarek7900.tid.source.Outcome;
import io.github.mtarek7900.tid.source.SourceResult;
import io.github.mtarek7900.tid.source.VirusTotalFacts;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;

class VerdictRuleTest {

    static final VerdictThresholds DEFAULTS = new VerdictThresholds(new VerdictThresholds.VirusTotal(3, 1));

    final VerdictRule rule = new VerdictRule(DEFAULTS);

    @ParameterizedTest(name = "VirusTotal {0} of 94 engines -> {1}")
    @CsvSource(textBlock = """
            0,  NONE
            1,  SUSPICIOUS
            2,  SUSPICIOUS
            3,  MALICIOUS
            94, MALICIOUS
            """)
    void virusTotalGivesASignalByHowManyEnginesFlaggedTheIndicator(int flagged, Signal signal) {
        var decision = rule.decide(List.of(virusTotalSeen(flagged)));

        assertThat(decision.readings()).singleElement().extracting(Reading::signal).isEqualTo(signal);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource
    void theWorstSignalWinsCleanNeedsASightingAndUnknownMeansNobodySawIt(
            String combination, List<SourceResult> results, Verdict verdict) {
        assertThat(rule.decide(results).verdict()).isEqualTo(verdict);
    }

    static Stream<Arguments> theWorstSignalWinsCleanNeedsASightingAndUnknownMeansNobodySawIt() {
        return Stream.of(
                arguments("Malicious", List.of(virusTotalSeen(5)), Verdict.MALICIOUS),
                arguments("Suspicious", List.of(virusTotalSeen(1)), Verdict.SUSPICIOUS),
                arguments("Seen, no Signal", List.of(virusTotalSeen(0)), Verdict.CLEAN),
                arguments("Not Seen", List.of(virusTotalNotSeen()), Verdict.UNKNOWN),
                arguments("no Source Results", List.of(), Verdict.UNKNOWN),
                arguments("Malicious + Suspicious", List.of(virusTotalSeen(1), virusTotalSeen(5)), Verdict.MALICIOUS),
                arguments("Malicious + no Signal", List.of(virusTotalSeen(0), virusTotalSeen(5)), Verdict.MALICIOUS),
                arguments("Malicious + Not Seen", List.of(virusTotalNotSeen(), virusTotalSeen(5)), Verdict.MALICIOUS),
                arguments("Suspicious + no Signal", List.of(virusTotalSeen(0), virusTotalSeen(2)), Verdict.SUSPICIOUS),
                arguments("Suspicious + Not Seen", List.of(virusTotalNotSeen(), virusTotalSeen(2)), Verdict.SUSPICIOUS),
                arguments("no Signal + Not Seen", List.of(virusTotalNotSeen(), virusTotalSeen(0)), Verdict.CLEAN),
                arguments("Not Seen + Not Seen", List.of(virusTotalNotSeen(), virusTotalNotSeen()), Verdict.UNKNOWN));
    }

    @ParameterizedTest(name = "Malicious at {0}, Suspicious at {1}: {2} engines -> {3}")
    @CsvSource(textBlock = """
            5, 2, 1, NONE
            5, 2, 2, SUSPICIOUS
            5, 2, 4, SUSPICIOUS
            5, 2, 5, MALICIOUS
            1, 1, 1, MALICIOUS
            """)
    void thresholdsComeFromConfiguration(int malicious, int suspicious, int flagged, Signal signal) {
        var configured = new VerdictRule(new VerdictThresholds(new VerdictThresholds.VirusTotal(malicious, suspicious)));

        assertThat(configured.decide(List.of(virusTotalSeen(flagged))).readings())
                .singleElement()
                .extracting(Reading::signal)
                .isEqualTo(signal);
    }

    @ParameterizedTest(name = "Malicious at {0}, Suspicious at {1}")
    @CsvSource({"3, 0", "0, 1", "3, -1"})
    void thresholdsBelowOneEngineAreRefused(int malicious, int suspicious) {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new VerdictThresholds.VirusTotal(malicious, suspicious))
                .withMessageContaining("at least 1 engine");
    }

    @ParameterizedTest(name = "{1}")
    @MethodSource
    void whyExplainsWhichSourceResultProducedWhichSignal(SourceResult result, String why) {
        assertThat(rule.decide(List.of(result)).readings())
                .singleElement()
                .extracting(Reading::explanation)
                .isEqualTo(why);
    }

    static Stream<Arguments> whyExplainsWhichSourceResultProducedWhichSignal() {
        return Stream.of(
                arguments(virusTotalSeen(5), "VirusTotal: 5 of 94 engines flagged it. 3 or more is Malicious."),
                arguments(virusTotalSeen(2), "VirusTotal: 2 of 94 engines flagged it. 1 to 2 is Suspicious."),
                arguments(virusTotalSeen(0), "VirusTotal: 0 of 94 engines flagged it. No Signal."),
                arguments(virusTotalNotSeen(), "VirusTotal has no record of it. No Signal."));
    }

    @ParameterizedTest(name = "Malicious at {0}, Suspicious at {1}: {2}")
    @CsvSource(delimiter = '|', textBlock = """
            3 | 2 | VirusTotal: 2 of 94 engines flagged it. 2 is Suspicious.
            5 | 1 | VirusTotal: 2 of 94 engines flagged it. 1 to 4 is Suspicious.
            """)
    void whyQuotesTheConfiguredThresholds(int malicious, int suspicious, String why) {
        var configured = new VerdictRule(new VerdictThresholds(new VerdictThresholds.VirusTotal(malicious, suspicious)));

        assertThat(configured.decide(List.of(virusTotalSeen(2))).readings())
                .singleElement()
                .extracting(Reading::explanation)
                .isEqualTo(why);
    }

    @ParameterizedTest(name = "{0} engines")
    @CsvSource({"0", "2", "5"})
    void eachReadingKeepsTheSourceResultItCameFrom(int flagged) {
        var result = virusTotalSeen(flagged);

        assertThat(rule.decide(List.of(result)).readings())
                .singleElement()
                .extracting(Reading::result)
                .isEqualTo(result);
    }

    static SourceResult virusTotalSeen(int flagged) {
        return new SourceResult(
                UUID.randomUUID(),
                "VirusTotal",
                new Indicator("evil.com", IndicatorType.DOMAIN),
                Outcome.SEEN,
                new VirusTotalFacts(flagged, 94, Instant.parse("2026-01-14T08:30:00Z")),
                "https://www.virustotal.com/gui/domain/evil.com",
                "{}",
                Instant.parse("2026-01-15T10:00:00Z"));
    }

    static SourceResult virusTotalNotSeen() {
        return new SourceResult(
                UUID.randomUUID(),
                "VirusTotal",
                new Indicator("evil.com", IndicatorType.DOMAIN),
                Outcome.NOT_SEEN,
                null,
                "https://www.virustotal.com/gui/domain/evil.com",
                "{}",
                Instant.parse("2026-01-15T10:00:00Z"));
    }
}
