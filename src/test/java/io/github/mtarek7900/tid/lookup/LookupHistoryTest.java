package io.github.mtarek7900.tid.lookup;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.mtarek7900.tid.FakeAbuseIpdb;
import io.github.mtarek7900.tid.FakeOtx;
import io.github.mtarek7900.tid.FakeVirusTotal;
import io.github.mtarek7900.tid.IntegrationTest;
import io.github.mtarek7900.tid.TestClock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

@IntegrationTest
class LookupHistoryTest {

    static final String IP_ADDRESS = "185.220.101.1";
    static final String DOMAIN = "evil.com";

    @LocalServerPort
    int port;

    @Autowired
    FakeVirusTotal virusTotal;

    @Autowired
    FakeAbuseIpdb abuseIpdb;

    @Autowired
    FakeOtx otx;

    @Autowired
    TestClock clock;

    RestClient api;

    @BeforeEach
    void setUp() {
        api = RestClient.create("http://localhost:" + port);
        virusTotal.answers("ip_addresses/" + IP_ADDRESS, 200, "ip-address-malicious.json");
        virusTotal.answers("domains/" + DOMAIN, 200, "domain-not-found.json");
        abuseIpdb.answers(IP_ADDRESS, 200, "high-confidence.json");
    }

    @Test
    void lookupHistoryIsEmptyBeforeTheFirstLookup() {
        var response = api.get().uri("/api/lookups").retrieve().toEntity(String.class);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
        assertThat(response.getBody()).isEqualTo("[]");
    }

    @Test
    void lookupHistoryIsMostRecentFirst() {
        lookUp(IP_ADDRESS);
        clock.advance(Duration.ofMinutes(5));
        var domain = lookUp(DOMAIN);

        var history = history();

        assertThat(indicators(history)).containsExactly(DOMAIN, IP_ADDRESS);
        var latest = history.get(0).get("latest");
        assertThat(latest.get("indicatorType").asText()).isEqualTo("DOMAIN");
        assertThat(latest.get("verdict").asText()).isEqualTo("UNKNOWN");
        assertThat(latest.get("lookedUpAt")).isEqualTo(domain.get("lookedUpAt"));
    }

    @Test
    void repeatedLookupsOfTheSameIndicatorAreGroupedWithACount() {
        var first = lookUp(IP_ADDRESS);
        clock.advance(Duration.ofMinutes(1));
        lookUp(DOMAIN);
        clock.advance(Duration.ofMinutes(1));
        lookUp("185.220.101[.]1");
        clock.advance(Duration.ofMinutes(1));
        var third = lookUp(IP_ADDRESS);

        var history = history();

        assertThat(indicators(history)).containsExactly(IP_ADDRESS, DOMAIN);
        var group = history.get(0);
        assertThat(group.get("indicatorType").asText()).isEqualTo("IP_ADDRESS");
        assertThat(group.get("count").asInt()).isEqualTo(3);
        assertThat(group.get("latest").get("id")).isEqualTo(third.get("id"));
        assertThat(group.get("lookups")).hasSize(3);
        assertThat(group.get("lookups").get(0).get("id")).isEqualTo(third.get("id"));
        assertThat(group.get("lookups").get(2).get("id")).isEqualTo(first.get("id"));
        assertThat(history.get(1).get("count").asInt()).isEqualTo(1);
    }

    @Test
    void aPastLookupIsReturnedAsItWasMade() {
        abuseIpdb.answers(IP_ADDRESS, 429, "rate-limited.json");
        var made = lookUp(IP_ADDRESS);

        var opened = open(made.get("id").asText());

        assertThat(opened).isEqualTo(made);
        assertThat(opened.get("partial").asBoolean()).isTrue();
        assertThat(opened.get("sourcesNotChecked")).hasSize(1);
        assertThat(opened.get("sourcesAsked")).hasSize(3);
    }

    @Test
    void aPastLookupIsUnchangedAfterNewerSourceResultsArriveForTheSameIndicator() {
        var made = lookUp(IP_ADDRESS);
        clock.advance(Duration.ofHours(1));
        virusTotal.answers("ip_addresses/" + IP_ADDRESS, 200, "ip-address-clean.json");
        abuseIpdb.answers(IP_ADDRESS, 200, "no-reports.json");
        var refreshed = lookUp(Map.of("input", IP_ADDRESS, "refresh", true));
        assertThat(refreshed.get("verdict")).isNotEqualTo(made.get("verdict"));

        var opened = (ObjectNode) open(made.get("id").asText());
        // The only addition is the summary of the newer Lookup, covered by NewerResultsTest
        opened.remove("newerResults");

        assertThat(opened).isEqualTo(made);
        assertThat(opened.get("verdict").asText()).isEqualTo("MALICIOUS");
    }

    @Test
    void aLookupThatReusedSourceResultsIsReturnedWithThemMarkedReused() {
        lookUp(IP_ADDRESS);
        clock.advance(Duration.ofHours(1));
        var reusing = lookUp(IP_ADDRESS);

        assertThat(open(reusing.get("id").asText())).isEqualTo(reusing);
    }

    @Test
    void openingALookupThatDoesNotExistIsNotFound() {
        var status = api.get()
                .uri("/api/lookups/{id}", UUID.randomUUID())
                .exchange((request, response) -> response.getStatusCode());

        assertThat(status).isEqualTo(HttpStatusCode.valueOf(404));
    }

    private List<JsonNode> history() {
        var history = new ArrayList<JsonNode>();
        api.get().uri("/api/lookups").retrieve().body(JsonNode.class).forEach(history::add);
        return history;
    }

    private static List<String> indicators(List<JsonNode> history) {
        return history.stream().map(group -> group.get("indicator").asText()).toList();
    }

    private JsonNode open(String id) {
        return api.get().uri("/api/lookups/{id}", id).retrieve().body(JsonNode.class);
    }

    private JsonNode lookUp(String input) {
        return lookUp(Map.of("input", input));
    }

    private JsonNode lookUp(Map<String, Object> request) {
        return api.post()
                .uri("/api/lookups")
                .contentType(MediaType.APPLICATION_JSON)
                .body(request)
                .retrieve()
                .body(JsonNode.class);
    }
}
