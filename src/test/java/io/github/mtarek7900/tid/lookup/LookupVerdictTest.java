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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;

@IntegrationTest
class LookupVerdictTest {

    @LocalServerPort
    int port;

    @Autowired
    FakeVirusTotal virusTotal;

    @Autowired
    FakeAbuseIpdb abuseIpdb;

    RestClient api;

    @BeforeEach
    void setUp() {
        api = RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .defaultStatusHandler(HttpStatusCode::isError, (request, response) -> {})
                .build();
    }

    @Test
    void anIpAddressThatVirusTotalEnginesFlagIsMalicious() {
        virusTotal.answers("ip_addresses/185.220.101.1", 200, "ip-address-malicious.json");
        abuseIpdb.answers("185.220.101.1", 200, "no-reports.json");

        var response = lookUp("185.220.101[.]1");

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        var lookup = response.getBody();
        assertThat(lookup.get("verdict").asText()).isEqualTo("MALICIOUS");
        assertThat(lookup.get("why"))
                .startsWith(new TextNode("VirusTotal: 15 of 92 engines flagged it. 3 or more is Malicious."));
        assertThat(lookup.get("sourceResults")).first().satisfies(result -> {
            assertThat(result.get("source").asText()).isEqualTo("VirusTotal");
            assertThat(result.get("outcome").asText()).isEqualTo("SEEN");
            assertThat(result.get("signal").asText()).isEqualTo("MALICIOUS");
            assertThat(result.get("facts").get("enginesFlagged").asInt()).isEqualTo(15);
            assertThat(result.get("facts").get("enginesTotal").asInt()).isEqualTo(92);
            assertThat(result.get("facts").get("lastAnalysedAt").asText()).isEqualTo("2026-10-15T18:44:02Z");
            assertThat(result.get("link").asText())
                    .isEqualTo("https://www.virustotal.com/gui/ip-address/185.220.101.1");
            assertThat(result.get("fetchedAt").asText()).isEqualTo("2026-01-15T10:00:00Z");
            assertThat(result.get("rawResponse").asText())
                    .isEqualTo(FakeVirusTotal.recording("ip-address-malicious.json"));
        });
    }

    @Test
    void aDomainVirusTotalHasSeenWithoutAnyEngineFlaggingItIsClean() {
        virusTotal.answers("domains/example.com", 200, "domain-clean.json");

        var lookup = lookUp("EXAMPLE[.]com").getBody();

        assertThat(lookup.get("verdict").asText()).isEqualTo("CLEAN");
        assertThat(lookup.get("why"))
                .containsExactly(new TextNode("VirusTotal: 0 of 92 engines flagged it. No Signal."));
        assertThat(lookup.get("sourceResults")).singleElement().satisfies(result -> {
            assertThat(result.get("outcome").asText()).isEqualTo("SEEN");
            assertThat(result.get("signal").asText()).isEqualTo("NONE");
            assertThat(result.get("link").asText()).isEqualTo("https://www.virustotal.com/gui/domain/example.com");
        });
    }

    @Test
    void aFileHashVirusTotalHasNeverSeenIsUnknown() {
        var hash = "9f2c4e1b7a5d3c8e6f0a2b4d6c8e0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c0d2e";
        virusTotal.answers("files/" + hash, 404, "file-not-found.json");

        var lookup = lookUp(hash.toUpperCase()).getBody();

        assertThat(lookup.get("verdict").asText()).isEqualTo("UNKNOWN");
        assertThat(lookup.get("why")).containsExactly(new TextNode("VirusTotal has no record of it. No Signal."));
        assertThat(lookup.get("sourcesAsked")).containsExactly(new TextNode("VirusTotal"));
        assertThat(lookup.get("sourceResults")).singleElement().satisfies(result -> {
            assertThat(result.get("outcome").asText()).isEqualTo("NOT_SEEN");
            assertThat(result.get("signal").asText()).isEqualTo("NONE");
            assertThat(result.get("facts").isNull()).isTrue();
            assertThat(result.get("link").asText()).isEqualTo("https://www.virustotal.com/gui/file/" + hash);
            assertThat(result.get("rawResponse").asText()).isEqualTo(FakeVirusTotal.recording("file-not-found.json"));
        });
    }

    @Test
    void anIpAddressVirusTotalHasNeverAnalysedIsUnknownRatherThanClean() {
        virusTotal.answers("ip_addresses/203.0.114.7", 200, "ip-address-never-analysed.json");
        abuseIpdb.answers("203.0.114.7", 200, "no-reports.json");

        var lookup = lookUp("203.0.114.7").getBody();

        assertThat(lookup.get("verdict").asText()).isEqualTo("UNKNOWN");
        assertThat(lookup.get("sourceResults"))
                .allSatisfy(result -> assertThat(result.get("outcome").asText()).isEqualTo("NOT_SEEN"));
    }

    @Test
    void theLookupHistoryKeepsTheVerdict() {
        virusTotal.answers("ip_addresses/185.220.101.1", 200, "ip-address-malicious.json");
        abuseIpdb.answers("185.220.101.1", 200, "no-reports.json");
        var lookup = lookUp("185.220.101.1").getBody();

        var history = api.get().uri("/api/lookups").retrieve().body(JsonNode.class);

        assertThat(history).singleElement().satisfies(entry -> {
            assertThat(entry.get("id")).isEqualTo(lookup.get("id"));
            assertThat(entry.get("verdict").asText()).isEqualTo("MALICIOUS");
        });
    }

    private ResponseEntity<JsonNode> lookUp(String input) {
        return api.post()
                .uri("/api/lookups")
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("input", input))
                .retrieve()
                .toEntity(JsonNode.class);
    }
}
