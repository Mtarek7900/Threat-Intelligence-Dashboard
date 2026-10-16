package io.github.mtarek7900.tid.lookup;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.mtarek7900.tid.FakeAbuseIpdb;
import io.github.mtarek7900.tid.FakeOtx;
import io.github.mtarek7900.tid.FakeVirusTotal;
import io.github.mtarek7900.tid.IntegrationTest;
import io.github.mtarek7900.tid.TestClock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.web.client.RestClient;

@IntegrationTest
class ReuseTest {

    static final String IP_ADDRESS = "185.220.101.1";

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

    @Autowired
    JdbcClient jdbc;

    RestClient api;

    @BeforeEach
    void setUp() {
        api = RestClient.create("http://localhost:" + port);
        virusTotal.answers("ip_addresses/" + IP_ADDRESS, 200, "ip-address-malicious.json");
        abuseIpdb.answers(IP_ADDRESS, 200, "high-confidence.json");
    }

    @Test
    void sourceResultsLessThanADayOldAreReusedInsteadOfAskingTheSourcesAgain() {
        var first = lookUp(IP_ADDRESS);
        clock.advance(Duration.ofHours(23));

        var second = lookUp(IP_ADDRESS);

        assertThat(virusTotal.requestsReceived()).isEqualTo(1);
        assertThat(abuseIpdb.checksReceived()).isEqualTo(1);
        assertThat(otx.requestsReceived()).isEqualTo(1);
        assertThat(second.get("id")).isNotEqualTo(first.get("id"));
        assertThat(second.get("verdict").asText()).isEqualTo("MALICIOUS");
        assertThat(second.get("why")).isEqualTo(first.get("why"));
        for (var i = 0; i < 3; i++) {
            var reused = second.get("sourceResults").get(i);
            var original = first.get("sourceResults").get(i);
            assertThat(original.get("reused").asBoolean()).isFalse();
            assertThat(reused.get("reused").asBoolean()).isTrue();
            assertThat(reused.get("fetchedAt")).isEqualTo(original.get("fetchedAt"));
            assertThat(reused.get("facts")).isEqualTo(original.get("facts"));
            assertThat(reused.get("rawResponse")).isEqualTo(original.get("rawResponse"));
        }
    }

    @Test
    void aReusedSourceResultShowsTheSameFactsAsWhenItWasFetched() {
        otx.answers("IPv4/" + IP_ADDRESS, 200, "ip-address-pulses.json");
        var first = lookUp(IP_ADDRESS);
        clock.advance(Duration.ofHours(1));

        var second = lookUp(IP_ADDRESS);

        var otxFacts = second.get("sourceResults").get(2).get("facts");
        assertThat(otxFacts.get("pulses")).isNotEmpty();
        assertThat(otxFacts).isEqualTo(first.get("sourceResults").get(2).get("facts"));
        assertThat(second.get("why")).isEqualTo(first.get("why"));
    }

    @Test
    void reusingSourceResultsStillKeepsANewLookupButNoNewSourceResults() {
        lookUp(IP_ADDRESS);
        clock.advance(Duration.ofHours(23));

        lookUp(IP_ADDRESS);

        assertThat(count("lookup")).isEqualTo(2);
        assertThat(count("source_result")).isEqualTo(3);
        assertThat(count("lookup_source_result")).isEqualTo(6);
    }

    @Test
    void sourceResultsMoreThanADayOldAreNotReused() {
        var first = lookUp(IP_ADDRESS);
        clock.advance(Duration.ofHours(25));

        var second = lookUp(IP_ADDRESS);

        assertThat(virusTotal.requestsReceived()).isEqualTo(2);
        assertThat(abuseIpdb.checksReceived()).isEqualTo(2);
        assertThat(otx.requestsReceived()).isEqualTo(2);
        for (var result : second.get("sourceResults")) {
            assertThat(result.get("reused").asBoolean()).isFalse();
        }
        assertThat(second.get("sourceResults").get(0).get("fetchedAt"))
                .isNotEqualTo(first.get("sourceResults").get(0).get("fetchedAt"));
    }

    @Test
    void reuseIsDecidedPerSourceSoOnlyAStaleSourceIsAskedAgain() {
        lookUp(IP_ADDRESS);
        clock.advance(Duration.ofHours(12));
        refreshAbuseIpdbOnly();
        clock.advance(Duration.ofHours(13));

        var lookup = lookUp(IP_ADDRESS);

        // VirusTotal's and OTX's only Seen or Not Seen results are 25 hours old; AbuseIPDB's 13
        assertThat(virusTotal.requestsReceived()).isEqualTo(3);
        assertThat(abuseIpdb.checksReceived()).isEqualTo(2);
        assertThat(otx.requestsReceived()).isEqualTo(3);
        assertThat(reusedFlags(lookup)).containsExactly(false, true, false);
    }

    @Test
    void notCheckedSourceResultsAreNeverReused() {
        abuseIpdb.answers(IP_ADDRESS, 429, "rate-limited.json");
        var first = lookUp(IP_ADDRESS);
        assertThat(first.get("sourceResults").get(1).get("outcome").asText()).isEqualTo("NOT_CHECKED");
        abuseIpdb.answers(IP_ADDRESS, 200, "high-confidence.json");
        clock.advance(Duration.ofHours(1));

        var second = lookUp(IP_ADDRESS);

        assertThat(abuseIpdb.checksReceived()).isEqualTo(2);
        assertThat(virusTotal.requestsReceived()).isEqualTo(1);
        assertThat(second.get("sourceResults").get(1).get("outcome").asText()).isEqualTo("SEEN");
        assertThat(reusedFlags(second)).containsExactly(true, false, true);
        assertThat(second.get("partial").asBoolean()).isFalse();
    }

    @Test
    void refreshAsksEverySourceAgainHoweverRecentItsSourceResultIs() {
        lookUp(IP_ADDRESS);
        clock.advance(Duration.ofMinutes(5));

        var refreshed = lookUp(Map.of("input", IP_ADDRESS, "refresh", true));

        assertThat(virusTotal.requestsReceived()).isEqualTo(2);
        assertThat(abuseIpdb.checksReceived()).isEqualTo(2);
        assertThat(otx.requestsReceived()).isEqualTo(2);
        assertThat(reusedFlags(refreshed)).containsExactly(false, false, false);
        assertThat(count("source_result")).isEqualTo(6);
    }

    @Test
    void theNewestSourceResultIsTheOneReused() {
        lookUp(IP_ADDRESS);
        clock.advance(Duration.ofHours(1));
        virusTotal.answers("ip_addresses/" + IP_ADDRESS, 200, "ip-address-clean.json");
        abuseIpdb.answers(IP_ADDRESS, 200, "no-reports.json");
        var refreshed = lookUp(Map.of("input", IP_ADDRESS, "refresh", true));
        clock.advance(Duration.ofHours(1));

        var lookup = lookUp(IP_ADDRESS);

        assertThat(reusedFlags(lookup)).containsExactly(true, true, true);
        assertThat(lookup.get("verdict")).isEqualTo(refreshed.get("verdict"));
        assertThat(lookup.get("sourceResults").get(0).get("fetchedAt"))
                .isEqualTo(refreshed.get("sourceResults").get(0).get("fetchedAt"));
    }

    private void refreshAbuseIpdbOnly() {
        // Only AbuseIPDB answers usefully, so only its Source Result is new and reusable
        virusTotal.answers("ip_addresses/" + IP_ADDRESS, 429, "rate-limited.json");
        otx.answersWith("IPv4/" + IP_ADDRESS, 500, "");
        lookUp(Map.of("input", IP_ADDRESS, "refresh", true));
        virusTotal.answers("ip_addresses/" + IP_ADDRESS, 200, "ip-address-malicious.json");
        otx.answers("IPv4/" + IP_ADDRESS, 200, "ip-address-no-pulses.json");
    }

    private static List<Boolean> reusedFlags(JsonNode lookup) {
        var flags = new ArrayList<Boolean>();
        lookup.get("sourceResults").forEach(result -> flags.add(result.get("reused").asBoolean()));
        return flags;
    }

    private long count(String table) {
        return jdbc.sql("select count(*) from " + table).query(Long.class).single();
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
