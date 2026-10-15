package io.github.mtarek7900.tid.lookup;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static org.assertj.core.api.Assertions.assertThat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.TextNode;
import com.github.tomakehurst.wiremock.WireMockServer;
import io.github.mtarek7900.tid.FakeVirusTotal;
import io.github.mtarek7900.tid.IntegrationTest;
import io.github.mtarek7900.tid.indicator.Indicator;
import io.github.mtarek7900.tid.indicator.IndicatorType;
import io.github.mtarek7900.tid.source.Outcome;
import io.github.mtarek7900.tid.source.Source;
import io.github.mtarek7900.tid.source.SourceResult;
import java.time.Clock;
import java.time.Duration;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

/**
 * Only VirusTotal exists so far, so a stand-in second Source, also behind WireMock, shows that the
 * Sources are asked at the same time.
 */
@IntegrationTest
@Import(ParallelSourcesTest.SecondSourceConfiguration.class)
class ParallelSourcesTest {

    static final String SECOND_SOURCE_PATH = "/second-source/example.com";

    @LocalServerPort
    int port;

    @Autowired
    FakeVirusTotal virusTotal;

    @Autowired
    WireMockServer fakeSources;

    RestClient api;

    @BeforeEach
    void setUp() {
        api = RestClient.create("http://localhost:" + port);
    }

    @Test
    void theLookupTakesAsLongAsTheSlowestSourceNotAllOfThemAddedUp() {
        virusTotal.answersAfter(
                Duration.ofMillis(1500), "domains/example.com", 200, "domain-clean.json");
        secondSourceAnswersAfter(Duration.ofMillis(1500));

        var started = System.nanoTime();
        var lookup = lookUp("example.com");
        var took = Duration.ofNanos(System.nanoTime() - started);

        assertThat(took).isLessThan(Duration.ofMillis(2800));
        assertThat(lookup.get("sourcesAsked")).containsExactlyInAnyOrder(new TextNode("VirusTotal"), new TextNode("Second Source"));
        assertThat(lookup.get("partial").asBoolean()).isFalse();
    }

    @Test
    void aSourceThatHangsOnlyMakesTheVerdictPartial() {
        virusTotal.answers("domains/example.com", 200, "domain-clean.json");
        secondSourceAnswersAfter(Duration.ofSeconds(5));

        var started = System.nanoTime();
        var lookup = lookUp("example.com");
        var took = Duration.ofNanos(System.nanoTime() - started);

        assertThat(took).isLessThan(Duration.ofSeconds(3));
        assertThat(lookup.get("verdict").asText()).isEqualTo("CLEAN");
        assertThat(lookup.get("partial").asBoolean()).isTrue();
        assertThat(lookup.get("sourcesNotChecked")).containsExactly(new TextNode("Second Source"));
    }

    private void secondSourceAnswersAfter(Duration delay) {
        fakeSources.stubFor(get(urlPathEqualTo(SECOND_SOURCE_PATH))
                .willReturn(aResponse().withStatus(404).withFixedDelay((int) delay.toMillis())));
    }

    private JsonNode lookUp(String input) {
        return api.post()
                .uri("/api/lookups")
                .contentType(MediaType.APPLICATION_JSON)
                .body(Map.of("input", input))
                .retrieve()
                .body(JsonNode.class);
    }

    @TestConfiguration(proxyBeanMethods = false)
    static class SecondSourceConfiguration {

        @Bean
        Source secondSource(WireMockServer fakeSources, Clock clock) {
            return new SecondSource(RestClient.create(fakeSources.baseUrl()), clock);
        }
    }

    /** Answers Not Seen once WireMock answers, however long that takes. */
    record SecondSource(RestClient http, Clock clock) implements Source {

        @Override
        public String name() {
            return "Second Source";
        }

        @Override
        public Set<IndicatorType> indicatorTypes() {
            return EnumSet.allOf(IndicatorType.class);
        }

        @Override
        public String link(Indicator indicator) {
            return "https://second-source.example/" + indicator.value();
        }

        @Override
        public SourceResult fetch(Indicator indicator) {
            http.get()
                    .uri("/second-source/{id}", indicator.value())
                    .exchange((request, response) -> null);
            return new SourceResult(
                    UUID.randomUUID(),
                    name(),
                    indicator,
                    Outcome.NOT_SEEN,
                    null,
                    null,
                    link(indicator),
                    "{}",
                    clock.instant());
        }
    }
}
