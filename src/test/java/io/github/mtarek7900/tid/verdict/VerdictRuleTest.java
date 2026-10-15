package io.github.mtarek7900.tid.verdict;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.junit.jupiter.params.provider.Arguments.arguments;

import io.github.mtarek7900.tid.indicator.Indicator;
import io.github.mtarek7900.tid.indicator.IndicatorType;
import io.github.mtarek7900.tid.source.AbuseIpdbFacts;
import io.github.mtarek7900.tid.source.NotCheckedReason;
import io.github.mtarek7900.tid.source.OtxFacts;
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
import org.junit.jupiter.params.provider.ValueSource;

class VerdictRuleTest {

    static final VerdictThresholds.AbuseIpdb ABUSEIPDB_DEFAULTS = new VerdictThresholds.AbuseIpdb(75, 25);

    static final VerdictThresholds DEFAULTS =
            new VerdictThresholds(new VerdictThresholds.VirusTotal(3, 1), ABUSEIPDB_DEFAULTS);

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

    @ParameterizedTest(name = "AbuseIPDB confidence {0}% -> {1}")
    @CsvSource(textBlock = """
            0,   NONE
            24,  NONE
            25,  SUSPICIOUS
            74,  SUSPICIOUS
            75,  MALICIOUS
            100, MALICIOUS
            """)
    void abuseIpdbGivesASignalByItsAbuseConfidence(int confidence, Signal signal) {
        var decision = rule.decide(List.of(abuseIpdbSeen(confidence)));

        assertThat(decision.readings()).singleElement().extracting(Reading::signal).isEqualTo(signal);
    }

    @ParameterizedTest(name = "OTX in {0} pulses")
    @ValueSource(ints = {1, 50})
    void otxGivesASuspiciousSignalWhenAnyPulseMentionsTheIndicator(int pulses) {
        var decision = rule.decide(List.of(otxSeen(pulses)));

        assertThat(decision.readings()).singleElement().extracting(Reading::signal).isEqualTo(Signal.SUSPICIOUS);
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource
    void otxIsACorroboratingSourceSoItsSignalCountsOnlyWhenAnotherSourceAlsoGivesOne(
            String combination, List<SourceResult> results, Verdict verdict) {
        assertThat(rule.decide(results).verdict()).isEqualTo(verdict);
    }

    static Stream<Arguments> otxIsACorroboratingSourceSoItsSignalCountsOnlyWhenAnotherSourceAlsoGivesOne() {
        return Stream.of(
                arguments("OTX alone", List.of(otxSeen(50)), Verdict.CLEAN),
                arguments("VirusTotal no Signal + OTX", List.of(virusTotalSeen(0), otxSeen(50)), Verdict.CLEAN),
                arguments("VirusTotal Not Seen + OTX", List.of(virusTotalNotSeen(), otxSeen(50)), Verdict.CLEAN),
                arguments("VirusTotal Not Checked + OTX", List.of(notChecked("VirusTotal", NotCheckedReason.TIMEOUT), otxSeen(50)), Verdict.CLEAN),
                arguments("VirusTotal Suspicious + OTX", List.of(virusTotalSeen(1), otxSeen(3)), Verdict.SUSPICIOUS),
                arguments("VirusTotal Malicious + OTX", List.of(virusTotalSeen(5), otxSeen(3)), Verdict.MALICIOUS),
                arguments("AbuseIPDB Suspicious + OTX", List.of(abuseIpdbSeen(30), otxSeen(1)), Verdict.SUSPICIOUS),
                arguments("VirusTotal no Signal + AbuseIPDB no Signal + OTX", List.of(virusTotalSeen(0), abuseIpdbSeen(0), otxSeen(50)), Verdict.CLEAN),
                arguments("VirusTotal Not Seen + OTX Not Seen", List.of(virusTotalNotSeen(), otxNotSeen()), Verdict.UNKNOWN));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource
    void whySaysWhetherOtxsSignalWasCounted(String combination, List<SourceResult> results, boolean counted, String why) {
        var otx = rule.decide(results).readings().getLast();

        assertThat(otx.signal()).isEqualTo(Signal.SUSPICIOUS);
        assertThat(otx.counted()).isEqualTo(counted);
        assertThat(otx.explanation()).isEqualTo(why);
    }

    static Stream<Arguments> whySaysWhetherOtxsSignalWasCounted() {
        var notCounted = "AlienVault OTX: in 50 pulses. Suspicious, but not counted: AlienVault OTX is a Corroborating"
                + " Source and no other Source gave a Signal.";
        return Stream.of(
                arguments("OTX alone", List.of(otxSeen(50)), false, notCounted),
                arguments("VirusTotal no Signal + OTX", List.of(virusTotalSeen(0), otxSeen(50)), false, notCounted),
                arguments("VirusTotal Suspicious + OTX", List.of(virusTotalSeen(1), otxSeen(3)), true,
                        "AlienVault OTX: in 3 pulses. Suspicious, counted because another Source also gave a Signal."),
                arguments("AbuseIPDB Malicious + OTX", List.of(abuseIpdbSeen(90), otxSeen(1)), true,
                        "AlienVault OTX: in 1 pulse. Suspicious, counted because another Source also gave a Signal."));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource
    void signalsFromSourcesThatAreNotCorroboratingAlwaysCount(String combination, List<SourceResult> results) {
        assertThat(rule.decide(results).readings()).allMatch(Reading::counted);
    }

    static Stream<Arguments> signalsFromSourcesThatAreNotCorroboratingAlwaysCount() {
        return Stream.of(
                arguments("VirusTotal alone", List.of(virusTotalSeen(5))),
                arguments("AbuseIPDB alone", List.of(abuseIpdbSeen(30))),
                arguments("VirusTotal + AbuseIPDB", List.of(virusTotalSeen(1), abuseIpdbSeen(90))));
    }

    @ParameterizedTest(name = "Malicious at {0}%, Suspicious at {1}%: {2}% -> {3}")
    @CsvSource(textBlock = """
            90, 50, 49, NONE
            90, 50, 50, SUSPICIOUS
            90, 50, 89, SUSPICIOUS
            90, 50, 90, MALICIOUS
            """)
    void abuseIpdbThresholdsComeFromConfiguration(int malicious, int suspicious, int confidence, Signal signal) {
        var configured = new VerdictRule(new VerdictThresholds(
                DEFAULTS.virustotal(), new VerdictThresholds.AbuseIpdb(malicious, suspicious)));

        assertThat(configured.decide(List.of(abuseIpdbSeen(confidence))).readings())
                .singleElement()
                .extracting(Reading::signal)
                .isEqualTo(signal);
    }

    @ParameterizedTest(name = "Malicious at {0}%, Suspicious at {1}%")
    @CsvSource({"75, 0", "0, 25", "101, 25", "75, 101", "50, 60"})
    void abuseIpdbThresholdsOutsideOneToAHundredPercentAreRefused(int malicious, int suspicious) {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new VerdictThresholds.AbuseIpdb(malicious, suspicious))
                .withMessageMatching(".*(1% to 100%|above the Malicious one).*");
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource
    void theWorstSignalAcrossSourcesWins(String combination, List<SourceResult> results, Verdict verdict) {
        assertThat(rule.decide(results).verdict()).isEqualTo(verdict);
    }

    static Stream<Arguments> theWorstSignalAcrossSourcesWins() {
        return Stream.of(
                arguments("VirusTotal no Signal + AbuseIPDB Malicious", List.of(virusTotalSeen(0), abuseIpdbSeen(90)), Verdict.MALICIOUS),
                arguments("VirusTotal Malicious + AbuseIPDB no Signal", List.of(virusTotalSeen(5), abuseIpdbSeen(0)), Verdict.MALICIOUS),
                arguments("VirusTotal Suspicious + AbuseIPDB Malicious", List.of(virusTotalSeen(1), abuseIpdbSeen(80)), Verdict.MALICIOUS),
                arguments("VirusTotal Malicious + AbuseIPDB Suspicious", List.of(virusTotalSeen(4), abuseIpdbSeen(30)), Verdict.MALICIOUS),
                arguments("VirusTotal Not Seen + AbuseIPDB Suspicious", List.of(virusTotalNotSeen(), abuseIpdbSeen(30)), Verdict.SUSPICIOUS),
                arguments("VirusTotal no Signal + AbuseIPDB Suspicious", List.of(virusTotalSeen(0), abuseIpdbSeen(30)), Verdict.SUSPICIOUS),
                arguments("VirusTotal no Signal + AbuseIPDB Not Seen", List.of(virusTotalSeen(0), abuseIpdbNotSeen()), Verdict.CLEAN),
                arguments("VirusTotal Not Seen + AbuseIPDB no Signal", List.of(virusTotalNotSeen(), abuseIpdbSeen(0)), Verdict.CLEAN),
                arguments("VirusTotal Not Seen + AbuseIPDB Not Seen", List.of(virusTotalNotSeen(), abuseIpdbNotSeen()), Verdict.UNKNOWN),
                arguments("VirusTotal Not Checked + AbuseIPDB Malicious", List.of(notChecked("VirusTotal", NotCheckedReason.TIMEOUT), abuseIpdbSeen(75)), Verdict.MALICIOUS),
                arguments("VirusTotal Not Seen + AbuseIPDB Not Checked", List.of(virusTotalNotSeen(), notChecked("AbuseIPDB", NotCheckedReason.TIMEOUT)), Verdict.UNKNOWN));
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
                arguments("Not Seen + Not Seen", List.of(virusTotalNotSeen(), virusTotalNotSeen()), Verdict.UNKNOWN),
                arguments("Not Checked", List.of(notChecked("VirusTotal", NotCheckedReason.TIMEOUT)), Verdict.UNKNOWN),
                arguments("Malicious + Not Checked", List.of(virusTotalSeen(5), notChecked("Other", NotCheckedReason.TIMEOUT)), Verdict.MALICIOUS),
                arguments("Suspicious + Not Checked", List.of(virusTotalSeen(1), notChecked("Other", NotCheckedReason.TIMEOUT)), Verdict.SUSPICIOUS),
                arguments("no Signal + Not Checked", List.of(virusTotalSeen(0), notChecked("Other", NotCheckedReason.TIMEOUT)), Verdict.CLEAN),
                arguments("Not Seen + Not Checked", List.of(virusTotalNotSeen(), notChecked("Other", NotCheckedReason.TIMEOUT)), Verdict.UNKNOWN));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource
    void theVerdictIsPartialAndNamesTheSourcesThatWereNotChecked(
            String combination, List<SourceResult> results, List<String> notChecked) {
        var decision = rule.decide(results);

        assertThat(decision.notChecked()).isEqualTo(notChecked);
        assertThat(decision.partial()).isEqualTo(!notChecked.isEmpty());
    }

    static Stream<Arguments> theVerdictIsPartialAndNamesTheSourcesThatWereNotChecked() {
        return Stream.of(
                arguments("all checked", List.of(virusTotalSeen(5), virusTotalNotSeen()), List.of()),
                arguments("no Source Results", List.of(), List.of()),
                arguments("all Not Checked",
                        List.of(notChecked("VirusTotal", NotCheckedReason.TIMEOUT), notChecked("AbuseIPDB", NotCheckedReason.MISSING_API_KEY)),
                        List.of("VirusTotal", "AbuseIPDB")),
                arguments("one Not Checked",
                        List.of(virusTotalSeen(5), notChecked("AbuseIPDB", NotCheckedReason.SOURCE_ERROR)),
                        List.of("AbuseIPDB")));
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
        var configured = new VerdictRule(new VerdictThresholds(
                new VerdictThresholds.VirusTotal(malicious, suspicious), ABUSEIPDB_DEFAULTS));

        assertThat(configured.decide(List.of(virusTotalSeen(flagged))).readings())
                .singleElement()
                .extracting(Reading::signal)
                .isEqualTo(signal);
    }

    @ParameterizedTest(name = "Malicious at {0}, Suspicious at {1}")
    @CsvSource({"3, 0", "0, 1", "3, -1", "3, 4"})
    void thresholdsBelowOneEngineOrSuspiciousAboveMaliciousAreRefused(int malicious, int suspicious) {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new VerdictThresholds.VirusTotal(malicious, suspicious))
                .withMessageMatching(".*(at least 1 engine|above the Malicious one).*");
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
                arguments(virusTotalNotSeen(), "VirusTotal has no record of it. No Signal."),
                arguments(abuseIpdbSeen(100), "AbuseIPDB: abuse confidence 100%. 75% or more is Malicious."),
                arguments(abuseIpdbSeen(40), "AbuseIPDB: abuse confidence 40%. 25% to 74% is Suspicious."),
                arguments(abuseIpdbSeen(0), "AbuseIPDB: abuse confidence 0%. No Signal."),
                arguments(abuseIpdbNotSeen(), "AbuseIPDB has no record of it. No Signal."),
                arguments(otxNotSeen(), "AlienVault OTX has no record of it. No Signal."),
                arguments(notChecked("VirusTotal", NotCheckedReason.TIMEOUT), "VirusTotal was Not Checked: it didn't answer in time."),
                arguments(notChecked("VirusTotal", NotCheckedReason.SOURCE_ERROR), "VirusTotal was Not Checked: it answered with an error."),
                arguments(notChecked("VirusTotal", NotCheckedReason.RATE_LIMITED), "VirusTotal was Not Checked: it is limiting how often it can be asked."),
                arguments(notChecked("VirusTotal", NotCheckedReason.MISSING_API_KEY), "VirusTotal was Not Checked: no API key is configured."));
    }

    @ParameterizedTest(name = "Malicious at {0}, Suspicious at {1}: {2}")
    @CsvSource(delimiter = '|', textBlock = """
            3 | 2 | VirusTotal: 2 of 94 engines flagged it. 2 is Suspicious.
            5 | 1 | VirusTotal: 2 of 94 engines flagged it. 1 to 4 is Suspicious.
            """)
    void whyQuotesTheConfiguredThresholds(int malicious, int suspicious, String why) {
        var configured = new VerdictRule(new VerdictThresholds(
                new VerdictThresholds.VirusTotal(malicious, suspicious), ABUSEIPDB_DEFAULTS));

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
                null,
                new VirusTotalFacts(flagged, 94, Instant.parse("2026-01-14T08:30:00Z")),
                "https://www.virustotal.com/gui/domain/evil.com",
                "{}",
                Instant.parse("2026-01-15T10:00:00Z"));
    }

    static SourceResult abuseIpdbSeen(int confidence) {
        return new SourceResult(
                UUID.randomUUID(),
                "AbuseIPDB",
                new Indicator("185.220.101.1", IndicatorType.IP_ADDRESS),
                Outcome.SEEN,
                null,
                new AbuseIpdbFacts(confidence, 12, "DE", "Example ISP"),
                "https://www.abuseipdb.com/check/185.220.101.1",
                "{}",
                Instant.parse("2026-01-15T10:00:00Z"));
    }

    static SourceResult abuseIpdbNotSeen() {
        return new SourceResult(
                UUID.randomUUID(),
                "AbuseIPDB",
                new Indicator("185.220.101.1", IndicatorType.IP_ADDRESS),
                Outcome.NOT_SEEN,
                null,
                null,
                "https://www.abuseipdb.com/check/185.220.101.1",
                "{}",
                Instant.parse("2026-01-15T10:00:00Z"));
    }

    static SourceResult otxSeen(int pulses) {
        return new SourceResult(
                UUID.randomUUID(),
                "AlienVault OTX",
                new Indicator("evil.com", IndicatorType.DOMAIN),
                Outcome.SEEN,
                null,
                new OtxFacts(pulses, List.of(new OtxFacts.Pulse("Example campaign", List.of("phishing")))),
                "https://otx.alienvault.com/indicator/domain/evil.com",
                "{}",
                Instant.parse("2026-01-15T10:00:00Z"));
    }

    static SourceResult otxNotSeen() {
        return new SourceResult(
                UUID.randomUUID(),
                "AlienVault OTX",
                new Indicator("evil.com", IndicatorType.DOMAIN),
                Outcome.NOT_SEEN,
                null,
                null,
                "https://otx.alienvault.com/indicator/domain/evil.com",
                "{}",
                Instant.parse("2026-01-15T10:00:00Z"));
    }

    static SourceResult notChecked(String source, NotCheckedReason reason) {
        return new SourceResult(
                UUID.randomUUID(),
                source,
                new Indicator("evil.com", IndicatorType.DOMAIN),
                Outcome.NOT_CHECKED,
                reason,
                null,
                "https://example.org/" + source,
                null,
                Instant.parse("2026-01-15T10:00:00Z"));
    }

    static SourceResult virusTotalNotSeen() {
        return new SourceResult(
                UUID.randomUUID(),
                "VirusTotal",
                new Indicator("evil.com", IndicatorType.DOMAIN),
                Outcome.NOT_SEEN,
                null,
                null,
                "https://www.virustotal.com/gui/domain/evil.com",
                "{}",
                Instant.parse("2026-01-15T10:00:00Z"));
    }
}
