package io.github.mtarek7900.tid.lookup;

import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.TextNode;
import io.github.mtarek7900.tid.FakeAbuseIpdb;
import io.github.mtarek7900.tid.FakeOtx;
import io.github.mtarek7900.tid.FakeVirusTotal;
import io.github.mtarek7900.tid.IntegrationTest;
import io.github.mtarek7900.tid.TestClock;
import java.time.Instant;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.test.context.TestPropertySource;
import org.springframework.web.client.RestClient;

/** VirusTotal's quota of 3 a day with a stop at 90% lets it be asked twice a day. */
@IntegrationTest
@TestPropertySource(properties = {"tid.sources.virustotal.daily-quota=3", "tid.sources.daily-stop-percent=90"})
class DailyStopTest {

    static final String FIRST = "185.220.101.1";
    static final String SECOND = "185.220.101.2";
    static final String THIRD = "185.220.101.3";

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
        for (var ipAddress : new String[] {FIRST, SECOND, THIRD}) {
            virusTotal.answers("ip_addresses/" + ipAddress, 200, "ip-address-malicious.json");
            abuseIpdb.answers(ipAddress, 200, "high-confidence.json");
        }
    }

    @Test
    void aSourceAtItsDailyStopIsNotAskedAndIsNotCheckedWithTheReason() {
        lookUp(FIRST);
        lookUp(SECOND);

        var lookup = lookUp(THIRD);

        assertThat(virusTotal.requestsReceived()).isEqualTo(2);
        assertThat(abuseIpdb.checksReceived()).isEqualTo(3);
        assertThat(otx.requestsReceived()).isEqualTo(3);
        var virusTotalResult = lookup.get("sourceResults").get(0);
        assertThat(virusTotalResult.get("outcome").asText()).isEqualTo("NOT_CHECKED");
        assertThat(virusTotalResult.get("notCheckedReason").asText()).isEqualTo("DAILY_LIMIT_REACHED");
        assertThat(lookup.get("partial").asBoolean()).isTrue();
        assertThat(lookup.get("sourcesNotChecked")).containsExactly(new TextNode("VirusTotal"));
        assertThat(lookup.get("why"))
                .contains(new TextNode("VirusTotal was Not Checked: it has reached its daily limit."));
        // AbuseIPDB still answers, so the Lookup still has a Verdict
        assertThat(lookup.get("verdict").asText()).isEqualTo("MALICIOUS");
    }

    @Test
    void reusedSourceResultsDontCountAndStillWorkAtTheStop() {
        lookUp(FIRST);
        lookUp(FIRST);
        lookUp(SECOND);

        var lookup = lookUp(FIRST);

        assertThat(virusTotal.requestsReceived()).isEqualTo(2);
        var virusTotalResult = lookup.get("sourceResults").get(0);
        assertThat(virusTotalResult.get("outcome").asText()).isEqualTo("SEEN");
        assertThat(virusTotalResult.get("reused").asBoolean()).isTrue();
        assertThat(lookup.get("partial").asBoolean()).isFalse();
    }

    @Test
    void aCallThatFailsStillCountsBecauseTheSourceCountedIt() {
        virusTotal.failsWith("ip_addresses/" + FIRST, 500);
        lookUp(FIRST);
        lookUp(FIRST);

        var lookup = lookUp(SECOND);

        assertThat(virusTotal.requestsReceived()).isEqualTo(2);
        assertThat(lookup.get("sourceResults").get(0).get("notCheckedReason").asText())
                .isEqualTo("DAILY_LIMIT_REACHED");
    }

    @Test
    void refreshDoesntGetPastTheStop() {
        lookUp(FIRST);
        lookUp(SECOND);

        var refreshed = lookUp(Map.of("input", FIRST, "refresh", true));

        assertThat(virusTotal.requestsReceived()).isEqualTo(2);
        assertThat(refreshed.get("sourceResults").get(0).get("notCheckedReason").asText())
                .isEqualTo("DAILY_LIMIT_REACHED");
    }

    @Test
    void theCountResetsAtMidnightUtc() {
        lookUp(FIRST);
        lookUp(SECOND);
        clock.setInstant(Instant.parse("2026-01-15T23:59:59Z"));
        var beforeMidnight = lookUp(THIRD);
        assertThat(beforeMidnight.get("sourceResults").get(0).get("notCheckedReason").asText())
                .isEqualTo("DAILY_LIMIT_REACHED");
        clock.setInstant(Instant.parse("2026-01-16T00:00:00Z"));

        var afterMidnight = lookUp(THIRD);

        assertThat(virusTotal.requestsReceived()).isEqualTo(3);
        assertThat(afterMidnight.get("sourceResults").get(0).get("outcome").asText()).isEqualTo("SEEN");
        assertThat(afterMidnight.get("partial").asBoolean()).isFalse();
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
