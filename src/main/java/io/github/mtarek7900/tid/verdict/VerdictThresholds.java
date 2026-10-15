package io.github.mtarek7900.tid.verdict;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Where each Source's Signal starts, from {@code tid.verdict} in application.yml. */
@ConfigurationProperties("tid.verdict")
public record VerdictThresholds(VirusTotal virustotal) {

    /** Engines flagging the Indicator needed for each Signal. */
    public record VirusTotal(int maliciousEngines, int suspiciousEngines) {

        public VirusTotal {
            if (suspiciousEngines < 1 || maliciousEngines < 1) {
                throw new IllegalArgumentException(
                        "VirusTotal thresholds must be at least 1 engine, so an Indicator no engine flagged has no Signal");
            }
        }
    }
}
