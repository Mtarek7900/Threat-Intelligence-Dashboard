package io.github.mtarek7900.tid.verdict;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** Where each Source's Signal starts, from {@code tid.verdict} in application.yml. */
@ConfigurationProperties("tid.verdict")
public record VerdictThresholds(VirusTotal virustotal, AbuseIpdb abuseipdb) {

    /** Engines flagging the Indicator needed for each Signal. */
    public record VirusTotal(int maliciousEngines, int suspiciousEngines) {

        public VirusTotal {
            if (suspiciousEngines < 1 || maliciousEngines < 1) {
                throw new IllegalArgumentException(
                        "VirusTotal thresholds must be at least 1 engine, so an Indicator no engine flagged has no Signal");
            }
            if (suspiciousEngines > maliciousEngines) {
                throw new IllegalArgumentException("The VirusTotal Suspicious threshold is above the Malicious one");
            }
        }
    }

    /** AbuseIPDB's abuse confidence, in percent, needed for each Signal. */
    public record AbuseIpdb(int maliciousConfidence, int suspiciousConfidence) {

        public AbuseIpdb {
            if (outsidePercentRange(maliciousConfidence) || outsidePercentRange(suspiciousConfidence)) {
                throw new IllegalArgumentException("AbuseIPDB thresholds must be from 1% to 100%");
            }
            if (suspiciousConfidence > maliciousConfidence) {
                throw new IllegalArgumentException("The AbuseIPDB Suspicious threshold is above the Malicious one");
            }
        }

        private static boolean outsidePercentRange(int confidence) {
            return confidence < 1 || confidence > 100;
        }
    }
}
