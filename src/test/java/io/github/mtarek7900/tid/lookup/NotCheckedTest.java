package io.github.mtarek7900.tid.lookup;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.TextNode;
import io.github.mtarek7900.tid.FakeVirusTotal;
import io.github.mtarek7900.tid.IntegrationTest;
import java.time.Duration;
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

/** A Source that can't answer never fails the Lookup: its Source Result is Not Checked instead. */
@IntegrationTest
class NotCheckedTest {

    static final String PATH = "domains/example.com";

    @LocalServerPort
    int port;

    @Autowired
    FakeVirusTotal virusTotal;

    RestClient api;

    @BeforeEach
    void setUp() {
        api = RestClient.builder()
                .baseUrl("http://localhost:" + port)
                .defaultStatusHandler(HttpStatusCode::isError, (request, response) -> {})
                .build();
    }

    @Test
    void aSourceThatDoesNotAnswerInTimeIsNotChecked() {
        virusTotal.answersAfter(Duration.ofSeconds(4), PATH, 200, "domain-clean.json");

        var started = System.nanoTime();
        var response = lookUp("example.com");
        var took = Duration.ofNanos(System.nanoTime() - started);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.CREATED);
        assertThat(took).isLessThan(Duration.ofSeconds(3));
        var lookup = response.getBody();
        assertThat(lookup.get("verdict").asText()).isEqualTo("UNKNOWN");
        assertThat(lookup.get("partial").asBoolean()).isTrue();
        assertThat(lookup.get("sourcesNotChecked")).containsExactly(new TextNode("VirusTotal"));
        assertThat(lookup.get("why"))
                .containsExactly(
                        new TextNode("VirusTotal was Not Checked: it didn't answer in time."), new TextNode("AlienVault OTX has no record of it. No Signal."));
        assertThat(lookup.get("sourceResults")).first().satisfies(result -> {
            assertThat(result.get("outcome").asText()).isEqualTo("NOT_CHECKED");
            assertThat(result.get("notCheckedReason").asText()).isEqualTo("TIMEOUT");
            assertThat(result.get("link").asText())
                    .isEqualTo("https://www.virustotal.com/gui/domain/example.com");
            assertThat(result.get("rawResponse").isNull()).isTrue();
        });
    }

    @Test
    void aSourceThatAnswersWithAnErrorIsNotChecked() {
        virusTotal.failsWith(PATH, 503);

        var lookup = lookUp("example.com").getBody();

        assertNotChecked(lookup, "SOURCE_ERROR");
    }

    @Test
    void aSourceThatDropsTheConnectionIsNotChecked() {
        virusTotal.dropsConnection(PATH);

        var lookup = lookUp("example.com").getBody();

        assertNotChecked(lookup, "SOURCE_ERROR");
    }

    @Test
    void aSourceThatIsRateLimitingIsNotChecked() {
        virusTotal.answers(PATH, 429, "rate-limited.json");

        var lookup = lookUp("example.com").getBody();

        assertNotChecked(lookup, "RATE_LIMITED");
    }

    @Test
    void aLookupWhoseSourcesWereAllCheckedIsNotPartial() {
        virusTotal.answers(PATH, 200, "domain-clean.json");

        var lookup = lookUp("example.com").getBody();

        assertThat(lookup.get("partial").asBoolean()).isFalse();
        assertThat(lookup.get("sourcesNotChecked")).isEmpty();
    }

    @Test
    void theLookupHistoryKeepsTheVerdictOfAPartialLookup() {
        virusTotal.failsWith(PATH, 503);
        var lookup = lookUp("example.com").getBody();

        var history = api.get().uri("/api/lookups").retrieve().body(JsonNode.class);

        assertThat(history).singleElement().satisfies(entry -> {
            assertThat(entry.get("id")).isEqualTo(lookup.get("id"));
            assertThat(entry.get("verdict").asText()).isEqualTo("UNKNOWN");
        });
    }

    private static void assertNotChecked(JsonNode lookup, String reason) {
        assertThat(lookup.get("verdict").asText()).isEqualTo("UNKNOWN");
        assertThat(lookup.get("partial").asBoolean()).isTrue();
        assertThat(lookup.get("sourcesNotChecked")).containsExactly(new TextNode("VirusTotal"));
        assertThat(lookup.get("sourceResults")).first().satisfies(result -> {
            assertThat(result.get("outcome").asText()).isEqualTo("NOT_CHECKED");
            assertThat(result.get("notCheckedReason").asText()).isEqualTo(reason);
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
