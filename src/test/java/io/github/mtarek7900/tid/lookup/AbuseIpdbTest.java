package io.github.mtarek7900.tid.lookup;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.TextNode;
import io.github.mtarek7900.tid.FakeAbuseIpdb;
import io.github.mtarek7900.tid.FakeVirusTotal;
import io.github.mtarek7900.tid.IntegrationTest;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

@IntegrationTest
class AbuseIpdbTest {

    @LocalServerPort
    int port;

    @Autowired
    FakeVirusTotal virusTotal;

    @Autowired
    FakeAbuseIpdb abuseIpdb;

    RestClient api;

    @BeforeEach
    void setUp() {
        api = RestClient.create("http://localhost:" + port);
    }

    @Test
    void anIpAddressIsCheckedWithVirusTotalAndAbuseIpdb() {
        virusTotal.answers("ip_addresses/185.220.101.1", 200, "ip-address-malicious.json");
        abuseIpdb.answers("185.220.101.1", 200, "high-confidence.json");

        var lookup = lookUp("185.220.101.1");

        assertThat(lookup.get("verdict").asText()).isEqualTo("MALICIOUS");
        assertThat(lookup.get("sourcesAsked")).containsExactly(new TextNode("VirusTotal"), new TextNode("AbuseIPDB"));
        assertThat(lookup.get("why"))
                .containsExactly(
                        new TextNode("VirusTotal: 15 of 92 engines flagged it. 3 or more is Malicious."),
                        new TextNode("AbuseIPDB: abuse confidence 100%. 75% or more is Malicious."));
        var abuse = lookup.get("sourceResults").get(1);
        assertThat(abuse.get("source").asText()).isEqualTo("AbuseIPDB");
        assertThat(abuse.get("outcome").asText()).isEqualTo("SEEN");
        assertThat(abuse.get("signal").asText()).isEqualTo("MALICIOUS");
        assertThat(abuse.get("facts").get("abuseConfidence").asInt()).isEqualTo(100);
        assertThat(abuse.get("facts").get("totalReports").asInt()).isEqualTo(1874);
        assertThat(abuse.get("facts").get("countryCode").asText()).isEqualTo("DE");
        assertThat(abuse.get("facts").get("isp").asText()).isEqualTo("Stiftung Erneuerbare Freiheit");
        assertThat(abuse.get("link").asText()).isEqualTo("https://www.abuseipdb.com/check/185.220.101.1");
    }

    @Test
    void anIpAddressAbuseIpdbHasReportsOfButLittleConfidenceInIsClean() {
        virusTotal.answers("ip_addresses/8.8.8.8", 200, "ip-address-never-analysed.json");
        abuseIpdb.answers("8.8.8.8", 200, "low-confidence.json");

        var lookup = lookUp("8.8.8.8");

        assertThat(lookup.get("verdict").asText()).isEqualTo("CLEAN");
        var abuse = lookup.get("sourceResults").get(1);
        assertThat(abuse.get("outcome").asText()).isEqualTo("SEEN");
        assertThat(abuse.get("signal").asText()).isEqualTo("NONE");
    }

    @Test
    void anIpAddressAbuseIpdbHasModerateConfidenceInIsSuspicious() {
        virusTotal.answers("ip_addresses/45.155.205.233", 200, "ip-address-never-analysed.json");
        abuseIpdb.answers("45.155.205.233", 200, "suspicious-confidence.json");

        var lookup = lookUp("45.155.205.233");

        assertThat(lookup.get("verdict").asText()).isEqualTo("SUSPICIOUS");
        assertThat(lookup.get("why").get(1).asText())
                .isEqualTo("AbuseIPDB: abuse confidence 40%. 25% to 74% is Suspicious.");
    }

    @ParameterizedTest(name = "{0} {1}")
    @CsvSource(delimiter = '|', textBlock = """
            503 | ''
            200 | {}
            200 | not json
            """)
    void anAbuseIpdbAnswerThatCannotBeUsedIsNotChecked(int status, String body) {
        virusTotal.answers("ip_addresses/185.220.101.1", 200, "ip-address-malicious.json");
        abuseIpdb.answersWith("185.220.101.1", status, body);

        var lookup = lookUp("185.220.101.1");

        assertThat(lookup.get("partial").asBoolean()).isTrue();
        assertThat(lookup.get("sourceResults").get(1).get("notCheckedReason").asText()).isEqualTo("SOURCE_ERROR");
    }

    @Test
    void anIpAddressNobodyHasReportedToAbuseIpdbIsNotSeenByIt() {
        virusTotal.answers("ip_addresses/203.0.114.7", 200, "ip-address-never-analysed.json");
        abuseIpdb.answers("203.0.114.7", 200, "no-reports.json");

        var lookup = lookUp("203.0.114.7");

        assertThat(lookup.get("verdict").asText()).isEqualTo("UNKNOWN");
        var abuse = lookup.get("sourceResults").get(1);
        assertThat(abuse.get("outcome").asText()).isEqualTo("NOT_SEEN");
        assertThat(abuse.get("facts").isNull()).isTrue();
        assertThat(lookup.get("why").get(1).asText()).isEqualTo("AbuseIPDB has no record of it. No Signal.");
    }

    @Test
    void abuseIpdbIsNotAskedAboutDomainsOrFileHashes() {
        virusTotal.answers("domains/example.com", 200, "domain-clean.json");
        var hash = "9f2c4e1b7a5d3c8e6f0a2b4d6c8e0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d2e";
        virusTotal.answers("files/" + hash, 404, "file-not-found.json");

        var domain = lookUp("example.com");
        var fileHash = lookUp(hash);

        for (var lookup : new JsonNode[] {domain, fileHash}) {
            assertThat(lookup.get("sourcesAsked")).containsExactly(new TextNode("VirusTotal"));
            assertThat(lookup.get("sourceResults")).hasSize(1);
            assertThat(lookup.get("partial").asBoolean()).isFalse();
        }
        assertThat(abuseIpdb.checksReceived()).isZero();
    }

    @Test
    void abuseIpdbLimitingHowOftenItCanBeAskedMakesTheVerdictPartial() {
        virusTotal.answers("ip_addresses/185.220.101.1", 200, "ip-address-malicious.json");
        abuseIpdb.answers("185.220.101.1", 429, "rate-limited.json");

        var lookup = lookUp("185.220.101.1");

        assertThat(lookup.get("verdict").asText()).isEqualTo("MALICIOUS");
        assertThat(lookup.get("partial").asBoolean()).isTrue();
        assertThat(lookup.get("sourcesNotChecked")).containsExactly(new TextNode("AbuseIPDB"));
        assertThat(lookup.get("sourceResults").get(1).get("notCheckedReason").asText()).isEqualTo("RATE_LIMITED");
    }

    private JsonNode lookUp(String input) {
        return api.post()
                .uri("/api/lookups")
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("input", input))
                .retrieve()
                .body(JsonNode.class);
    }
}
