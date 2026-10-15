package io.github.mtarek7900.tid;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;
import com.github.tomakehurst.wiremock.http.Fault;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import org.springframework.core.io.ClassPathResource;

/**
 * VirusTotal faked at the network edge. It serves the recorded responses in
 * {@code src/test/resources/wiremock/__files/virustotal}, only to requests carrying the API key.
 */
public class FakeVirusTotal {

    public static final String API_KEY = "test-virustotal-key";

    private final WireMockServer server;

    FakeVirusTotal(WireMockServer server) {
        this.server = server;
    }

    /** Answers a GET of {@code /api/v3/<path>}, e.g. {@code ip_addresses/1.2.3.4}, with a recording. */
    public void answers(String path, int status, String recording) {
        answersAfter(Duration.ZERO, path, status, recording);
    }

    /** Like {@link #answers}, but only after the delay. */
    public void answersAfter(Duration delay, String path, int status, String recording) {
        respond(path, recorded(status, recording).withFixedDelay((int) delay.toMillis()));
    }

    /** Answers with an error status and no body. */
    public void failsWith(String path, int status) {
        respond(path, aResponse().withStatus(status));
    }

    /** Resets the connection without answering. */
    public void dropsConnection(String path) {
        respond(path, aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER));
    }

    /** How many requests reached VirusTotal at all. */
    public int requestsReceived() {
        return server.findAll(getRequestedFor(urlPathMatching("/api/v3/.*"))).size();
    }

    private void respond(String path, ResponseDefinitionBuilder response) {
        server.stubFor(get(urlPathEqualTo("/api/v3/" + path))
                .withHeader("x-apikey", equalTo(API_KEY))
                .willReturn(response));
    }

    private static ResponseDefinitionBuilder recorded(int status, String recording) {
        return aResponse()
                .withStatus(status)
                .withHeader("Content-Type", "application/json")
                .withBodyFile("virustotal/" + recording);
    }

    /** The recorded response body, exactly as VirusTotal sent it. */
    public static String recording(String recording) {
        try {
            return new ClassPathResource("wiremock/__files/virustotal/" + recording)
                    .getContentAsString(StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
