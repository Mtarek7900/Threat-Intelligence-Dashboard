package io.github.mtarek7900.tid;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;

import com.github.tomakehurst.wiremock.WireMockServer;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
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
        server.stubFor(get(urlPathEqualTo("/api/v3/" + path))
                .withHeader("x-apikey", equalTo(API_KEY))
                .willReturn(aResponse()
                        .withStatus(status)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("virustotal/" + recording)));
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
