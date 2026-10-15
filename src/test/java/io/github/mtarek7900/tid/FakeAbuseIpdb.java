package io.github.mtarek7900.tid;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;

import com.github.tomakehurst.wiremock.WireMockServer;

/**
 * AbuseIPDB faked at the network edge. It serves the responses in
 * {@code src/test/resources/wiremock/__files/abuseipdb}, only to requests carrying the API key.
 */
public class FakeAbuseIpdb {

    public static final String API_KEY = "test-abuseipdb-key";

    private static final String CHECK = "/abuseipdb/api/v2/check";

    private final WireMockServer server;

    FakeAbuseIpdb(WireMockServer server) {
        this.server = server;
    }

    /** Answers a check of {@code ipAddress} with a recording. */
    public void answers(String ipAddress, int status, String recording) {
        server.stubFor(get(urlPathEqualTo(CHECK))
                .withQueryParam("ipAddress", equalTo(ipAddress))
                .withHeader("Key", equalTo(API_KEY))
                .withHeader("Accept", equalTo("application/json"))
                .willReturn(aResponse()
                        .withStatus(status)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("abuseipdb/" + recording)));
    }

    /** Answers a check of {@code ipAddress} with the given status and body. */
    public void answersWith(String ipAddress, int status, String body) {
        server.stubFor(get(urlPathEqualTo(CHECK))
                .withQueryParam("ipAddress", equalTo(ipAddress))
                .withHeader("Key", equalTo(API_KEY))
                .willReturn(aResponse().withStatus(status).withBody(body)));
    }

    /** How many checks reached AbuseIPDB at all. */
    public int checksReceived() {
        return server.findAll(getRequestedFor(urlPathEqualTo(CHECK))).size();
    }
}
