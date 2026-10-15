package io.github.mtarek7900.tid.lookup;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.TextNode;
import io.github.mtarek7900.tid.FakeAbuseIpdb;
import io.github.mtarek7900.tid.FakeOtx;
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
class OtxTest {

    static final String HASH = "9f2c4e1b7a5d3c8e6f0a2b4d6c8e0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d2e";
    static final String NO_SUCH_DOMAIN = "tid-fixture-q8v3x1k9z2w7.com";

    @LocalServerPort
    int port;

    @Autowired
    FakeVirusTotal virusTotal;

    @Autowired
    FakeAbuseIpdb abuseIpdb;

    @Autowired
    FakeOtx otx;

    RestClient api;

    @BeforeEach
    void setUp() {
        api = RestClient.create("http://localhost:" + port);
    }

    @Test
    void aBenignReferenceThatManyPulsesMentionStaysClean() {
        virusTotal.answers("ip_addresses/9.9.9.9", 200, "ip-address-clean.json");
        abuseIpdb.answers("9.9.9.9", 200, "whitelisted.json");
        otx.answers("IPv4/9.9.9.9", 200, "ip-address-pulses.json");

        var lookup = lookUp("9.9.9.9");

        assertThat(lookup.get("verdict").asText()).isEqualTo("CLEAN");
        assertThat(lookup.get("partial").asBoolean()).isFalse();
        assertThat(lookup.get("sourcesAsked"))
                .containsExactly(new TextNode("VirusTotal"), new TextNode("AbuseIPDB"), new TextNode("AlienVault OTX"));
        assertThat(lookup.get("why").get(2).asText())
                .isEqualTo("AlienVault OTX: in 50 pulses. Suspicious, but not counted: AlienVault OTX is a"
                        + " Corroborating Source and no other Source gave a Signal.");
        var otxResult = lookup.get("sourceResults").get(2);
        assertThat(otxResult.get("source").asText()).isEqualTo("AlienVault OTX");
        assertThat(otxResult.get("outcome").asText()).isEqualTo("SEEN");
        assertThat(otxResult.get("signal").asText()).isEqualTo("SUSPICIOUS");
        var facts = otxResult.get("facts");
        assertThat(facts.get("pulseCount").asInt()).isEqualTo(50);
        assertThat(facts.get("pulses")).hasSize(50);
        assertThat(facts.get("pulses").get(0).get("name").asText())
                .isEqualTo("CnC.MiraiBotnet.Monster & Scan.MiraiBotnet.Monster (DOD Network Information Center)");
        assertThat(facts.get("pulses").get(0).get("tags")).contains(new TextNode("unix mirai"), new TextNode("mirai"));
        assertThat(otxResult.get("link").asText()).isEqualTo("https://otx.alienvault.com/indicator/ip/9.9.9.9");
        assertThat(otxResult.get("rawResponse").asText()).contains("\"pulse_info\"");
    }

    @Test
    void otxsSignalCountsWhenAnotherSourceAlsoGivesOne() {
        virusTotal.answers("ip_addresses/118.193.40.10", 200, "ip-address-never-analysed.json");
        abuseIpdb.answers("118.193.40.10", 200, "suspicious-confidence.json");
        otx.answers("IPv4/118.193.40.10", 200, "ip-address-one-pulse.json");

        var lookup = lookUp("118.193.40.10");

        assertThat(lookup.get("verdict").asText()).isEqualTo("SUSPICIOUS");
        assertThat(lookup.get("why").get(2).asText())
                .isEqualTo("AlienVault OTX: in 1 pulse. Suspicious, counted because another Source also gave a Signal.");
        var pulse = lookup.get("sourceResults").get(2).get("facts").get("pulses").get(0);
        assertThat(pulse.get("name").asText()).isEqualTo("Malware Filter - Botnet List - 09-10-2026 (Part 2)");
        assertThat(pulse.get("tags")).isEmpty();
    }

    @Test
    void domainsAndFileHashesAreCheckedWithVirusTotalAndOtx() {
        virusTotal.answers("domains/" + NO_SUCH_DOMAIN, 404, "domain-not-found.json");
        otx.answers("domain/" + NO_SUCH_DOMAIN, 200, "domain-no-pulses.json");
        virusTotal.answers("files/" + HASH, 404, "file-not-found.json");
        otx.answers("file/" + HASH, 200, "file-no-pulses.json");

        var domain = lookUp(NO_SUCH_DOMAIN);
        var fileHash = lookUp(HASH);

        for (var lookup : new JsonNode[] {domain, fileHash}) {
            assertThat(lookup.get("verdict").asText()).isEqualTo("UNKNOWN");
            assertThat(lookup.get("sourcesAsked"))
                    .containsExactly(new TextNode("VirusTotal"), new TextNode("AlienVault OTX"));
            assertThat(lookup.get("why").get(1).asText()).isEqualTo("AlienVault OTX has no record of it. No Signal.");
            var otxResult = lookup.get("sourceResults").get(1);
            assertThat(otxResult.get("outcome").asText()).isEqualTo("NOT_SEEN");
            assertThat(otxResult.get("facts").isNull()).isTrue();
        }
        assertThat(domain.get("sourceResults").get(1).get("link").asText())
                .isEqualTo("https://otx.alienvault.com/indicator/domain/" + NO_SUCH_DOMAIN);
        assertThat(fileHash.get("sourceResults").get(1).get("link").asText())
                .isEqualTo("https://otx.alienvault.com/indicator/file/" + HASH);
        assertThat(otx.requestsReceived("domain/" + NO_SUCH_DOMAIN)).isOne();
        assertThat(otx.requestsReceived("file/" + HASH)).isOne();
    }

    @ParameterizedTest(name = "{0} -> {1}")
    @CsvSource(delimiter = '|', textBlock = """
            www.tid-fixture-q8v3x1k9z2w7.com | hostname | hostname | hostname-no-pulses.json
            tid-fixture-q8v3x1k9z2w7.co.uk   | domain   | domain   | domain-no-pulses.json
            2001:4860:4860::8888             | IPv6     | ip       | ipv6-address-no-pulses.json
            """)
    void otxIsAskedInTheSectionThatHoldsTheIndicator(
            String indicator, String section, String page, String recording) {
        otx.answers(section + "/" + indicator, 200, recording);

        var lookup = lookUp(indicator);

        assertThat(otx.requestsReceived(section + "/" + indicator)).isOne();
        var otxResult = lookup.get("sourceResults").get(lookup.get("sourceResults").size() - 1);
        assertThat(otxResult.get("outcome").asText()).isEqualTo("NOT_SEEN");
        assertThat(otxResult.get("link").asText())
                .isEqualTo("https://otx.alienvault.com/indicator/" + page + "/" + indicator);
    }

    @ParameterizedTest(name = "{0} {1}")
    @CsvSource(delimiter = '|', textBlock = """
            503 | ''
            404 | {"detail": "Not found."}
            200 | {}
            200 | not json
            """)
    void anOtxAnswerThatCannotBeUsedIsNotChecked(int status, String body) {
        virusTotal.answers("domains/example.com", 200, "domain-clean.json");
        otx.answersWith("domain/example.com", status, body);

        var lookup = lookUp("example.com");

        assertThat(lookup.get("verdict").asText()).isEqualTo("CLEAN");
        assertThat(lookup.get("partial").asBoolean()).isTrue();
        assertThat(lookup.get("sourcesNotChecked")).containsExactly(new TextNode("AlienVault OTX"));
        assertThat(lookup.get("sourceResults").get(1).get("notCheckedReason").asText()).isEqualTo("SOURCE_ERROR");
    }

    @Test
    void otxLimitingHowOftenItCanBeAskedMakesTheVerdictPartial() {
        virusTotal.answers("domains/example.com", 200, "domain-clean.json");
        otx.answersWith("domain/example.com", 429, "");

        var lookup = lookUp("example.com");

        assertThat(lookup.get("partial").asBoolean()).isTrue();
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
