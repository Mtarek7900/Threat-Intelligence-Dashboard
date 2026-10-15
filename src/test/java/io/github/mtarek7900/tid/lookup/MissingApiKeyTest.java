package io.github.mtarek7900.tid.lookup;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.TextNode;
import io.github.mtarek7900.tid.FakeAbuseIpdb;
import io.github.mtarek7900.tid.FakeOtx;
import io.github.mtarek7900.tid.FakeVirusTotal;
import io.github.mtarek7900.tid.IntegrationTest;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.client.RestClient;

@IntegrationTest
@TestPropertySource(
        properties = {"tid.sources.virustotal.api-key=", "tid.sources.abuseipdb.api-key=", "tid.sources.otx.api-key="})
class MissingApiKeyTest {

    @LocalServerPort
    int port;

    @Autowired
    FakeVirusTotal virusTotal;

    @Autowired
    FakeAbuseIpdb abuseIpdb;

    @Autowired
    FakeOtx otx;

    @Test
    void sourcesWithNoApiKeyAreNotCheckedAndNeverAsked() {
        var response = RestClient.create("http://localhost:" + port)
                .post()
                .uri("/api/lookups")
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("input", "185.220.101.1"))
                .retrieve()
                .toEntity(JsonNode.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        var lookup = response.getBody();
        assertThat(lookup.get("verdict").asText()).isEqualTo("UNKNOWN");
        assertThat(lookup.get("partial").asBoolean()).isTrue();
        assertThat(lookup.get("sourcesNotChecked"))
                .containsExactly(new TextNode("VirusTotal"), new TextNode("AbuseIPDB"), new TextNode("AlienVault OTX"));
        assertThat(lookup.get("why"))
                .containsExactly(
                        new TextNode("VirusTotal was Not Checked: no API key is configured."),
                        new TextNode("AbuseIPDB was Not Checked: no API key is configured."),
                        new TextNode("AlienVault OTX was Not Checked: no API key is configured."));
        assertThat(lookup.get("sourceResults"))
                .allSatisfy(result -> assertThat(result.get("notCheckedReason").asText()).isEqualTo("MISSING_API_KEY"));
        assertThat(virusTotal.requestsReceived()).isZero();
        assertThat(abuseIpdb.checksReceived()).isZero();
        assertThat(otx.requestsReceived()).isZero();
    }
}
