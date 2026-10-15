package io.github.mtarek7900.tid.source;

/**
 * What AbuseIPDB knows about an IP address that has been reported to it.
 *
 * @param abuseConfidence AbuseIPDB's confidence, from 0 to 100%, that the IP address is abusive
 * @param countryCode ISO 3166 alpha-2 code of the country the IP address is in
 */
public record AbuseIpdbFacts(int abuseConfidence, int totalReports, String countryCode, String isp)
        implements SourceFacts {}
