package io.github.mtarek7900.tid.lookup;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.mtarek7900.tid.IntegrationTest;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClient;

@IntegrationTest
class MakingALookupTest {

    @LocalServerPort
    int port;

    RestClient api;

    @BeforeEach
    void setUp() {
        api = RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .defaultStatusHandler(HttpStatusCode::isError, (request, response) -> {})
                .build();
    }

    @ParameterizedTest(name = "[{0}] -> {1} ({2})")
    @CsvSource(textBlock = """
            evil[.]com,       evil.com,       DOMAIN
            ' 8.8.8[.]8 ',    8.8.8.8,        IP_ADDRESS
            D41D8CD98F00B204E9800998ECF8427E, d41d8cd98f00b204e9800998ecf8427e, FILE_HASH
            """)
    void aValidIndicatorMakesALookupWithAnUnknownVerdict(String input, String indicator, String type) {
        var response = lookUp(input);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        var lookup = response.getBody();
        assertThat(lookup.get("id").asText()).isNotBlank();
        assertThat(lookup.get("indicator").asText()).isEqualTo(indicator);
        assertThat(lookup.get("indicatorType").asText()).isEqualTo(type);
        assertThat(lookup.get("verdict").asText()).isEqualTo("UNKNOWN");
        assertThat(lookup.get("lookedUpAt").asText()).isEqualTo("2026-01-15T10:00:00Z");
    }

    @Test
    void theLookupIsKeptInTheLookupHistory() {
        var lookup = lookUp("evil[.]com").getBody();

        var history = api.get().uri("/api/lookups").retrieve().body(JsonNode.class);

        assertThat(history).hasSize(1);
        assertThat(history.get(0)).isEqualTo(lookup);
    }

    @ParameterizedTest(name = "[{0}] -> {1}")
    @CsvSource(delimiter = '|', textBlock = """
            10.0.0.1         | RESERVED_IP_ADDRESS | 10.0.0.1 is a private address (10.0.0.0/8). Sources only know about public IP addresses.
            hxxps://evil[.]com/login | URL_NOT_SUPPORTED | URLs aren't supported yet. Look up the URL's domain or IP address instead.
            not an indicator | UNRECOGNISED        | That isn't an IP address, domain or file hash. Paste an IPv4 or IPv6 address, a domain such as example.com, or an MD5, SHA-1 or SHA-256 file hash.
            """)
    void invalidInputIsRejectedWithTheReason(String input, String reason, String message) {
        var response = lookUp(input);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);
        assertThat(response.getBody().get("reason").asText()).isEqualTo(reason);
        assertThat(response.getBody().get("detail").asText()).isEqualTo(message);
        assertThat(api.get().uri("/api/lookups").retrieve().body(JsonNode.class)).isEmpty();
    }

    @Test
    void missingInputIsRejected() {
        var response = api.post()
                .uri("/api/lookups")
                .contentType(MediaType.APPLICATION_JSON)
                .body("{}")
                .retrieve()
                .toEntity(JsonNode.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST);
        assertThat(response.getBody().get("detail").asText())
                .isEqualTo("Paste an IP address, domain or file hash to look up.");
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
