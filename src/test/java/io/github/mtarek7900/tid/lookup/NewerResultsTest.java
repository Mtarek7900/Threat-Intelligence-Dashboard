package io.github.mtarek7900.tid.lookup;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.mtarek7900.tid.FakeAbuseIpdb;
import io.github.mtarek7900.tid.FakeOtx;
import io.github.mtarek7900.tid.FakeVirusTotal;
import io.github.mtarek7900.tid.IntegrationTest;
import io.github.mtarek7900.tid.TestClock;
import java.time.Duration;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

@IntegrationTest
class NewerResultsTest {

    static final String IP_ADDRESS = "185.220.101.1";
    static final String OTHER_IP_ADDRESS = "8.8.8.8";

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
        abuseIpdb.answers(IP_ADDRESS, 200, "high-confidence.json");
        virusTotal.answers("ip_addresses/" + OTHER_IP_ADDRESS, 200, "ip-address-clean.json");
        abuseIpdb.answers(OTHER_IP_ADDRESS, 200, "no-reports.json");
    }

    @Test
    void aLookupWithNoNewerSourceResultsHasNoNewerResults() {
        var made = lookUp(IP_ADDRESS);
        clock.advance(Duration.ofHours(1));
        lookUp(OTHER_IP_ADDRESS);

        var opened = open(made);

        assertThat(opened.has("newerResults")).isFalse();
    }

    @Test
    void aRefreshByALaterLookupGivesTheEarlierOneTheNewerVerdictAndWhenItWasReached() {
        var made = lookUp(IP_ADDRESS);
        clock.advance(Duration.ofHours(1));
        virusTotal.answers("ip_addresses/" + IP_ADDRESS, 200, "ip-address-clean.json");
        abuseIpdb.answers(IP_ADDRESS, 200, "no-reports.json");
        var refreshed = lookUp(Map.of("input", IP_ADDRESS, "refresh", true));

        var newer = open(made).get("newerResults");

        assertThat(newer.get("lookupId")).isEqualTo(refreshed.get("id"));
        assertThat(newer.get("verdict").asText()).isEqualTo("CLEAN");
        assertThat(newer.get("verdict")).isEqualTo(refreshed.get("verdict"));
        assertThat(newer.get("lookedUpAt")).isEqualTo(refreshed.get("lookedUpAt"));
    }

    @Test
    void theNewestLookupOfAnIndicatorHasNoNewerResults() {
        lookUp(IP_ADDRESS);
        clock.advance(Duration.ofHours(1));
        var refreshed = lookUp(Map.of("input", IP_ADDRESS, "refresh", true));

        assertThat(open(refreshed).has("newerResults")).isFalse();
    }

    @Test
    void aLaterLookupThatOnlyReusedTheSameSourceResultsIsNotNewer() {
        var made = lookUp(IP_ADDRESS);
        clock.advance(Duration.ofHours(1));
        var reusing = lookUp(IP_ADDRESS);
        assertThat(reusing.get("sourceResults").get(0).get("reused").asBoolean()).isTrue();

        assertThat(open(made).has("newerResults")).isFalse();
    }

    @Test
    void aLookupThatReusedSourceResultsSeesTheNewerOnesALaterRefreshFetched() {
        lookUp(IP_ADDRESS);
        clock.advance(Duration.ofHours(1));
        var reusing = lookUp(IP_ADDRESS);
        clock.advance(Duration.ofHours(1));
        abuseIpdb.answers(IP_ADDRESS, 200, "no-reports.json");
        var refreshed = lookUp(Map.of("input", IP_ADDRESS, "refresh", true));

        var newer = open(reusing).get("newerResults");

        assertThat(newer.get("lookupId")).isEqualTo(refreshed.get("id"));
        assertThat(newer.get("verdict")).isEqualTo(refreshed.get("verdict"));
    }

    @Test
    void aLaterLookupWhoseSourcesWereAllNotCheckedIsNotNewer() {
        var made = lookUp(IP_ADDRESS);
        clock.advance(Duration.ofHours(1));
        virusTotal.failsWith("ip_addresses/" + IP_ADDRESS, 500);
        abuseIpdb.answers(IP_ADDRESS, 429, "rate-limited.json");
        otx.answersWith("IPv4/" + IP_ADDRESS, 500, "");
        var refreshed = lookUp(Map.of("input", IP_ADDRESS, "refresh", true));
        assertThat(refreshed.get("sourcesNotChecked")).hasSize(3);

        assertThat(open(made).has("newerResults")).isFalse();
    }

    @Test
    void theNewerResultsAreTheMostRecentLaterLookupWithAnsweredNewerSourceResults() {
        var made = lookUp(IP_ADDRESS);
        clock.advance(Duration.ofHours(1));
        abuseIpdb.answers(IP_ADDRESS, 200, "no-reports.json");
        var refreshed = lookUp(Map.of("input", IP_ADDRESS, "refresh", true));
        clock.advance(Duration.ofHours(1));
        virusTotal.failsWith("ip_addresses/" + IP_ADDRESS, 500);
        abuseIpdb.answers(IP_ADDRESS, 429, "rate-limited.json");
        otx.answersWith("IPv4/" + IP_ADDRESS, 500, "");
        lookUp(Map.of("input", IP_ADDRESS, "refresh", true));

        var newer = open(made).get("newerResults");

        assertThat(newer.get("lookupId")).isEqualTo(refreshed.get("id"));
    }

    @Test
    void aNewLookupHasNoNewerResults() {
        lookUp(IP_ADDRESS);
        clock.advance(Duration.ofHours(1));

        var refreshed = lookUp(Map.of("input", IP_ADDRESS, "refresh", true));

        assertThat(refreshed.has("newerResults")).isFalse();
    }

    private JsonNode open(JsonNode lookup) {
        return api.get().uri("/api/lookups/{id}", lookup.get("id").asText()).retrieve().body(JsonNode.class);
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
