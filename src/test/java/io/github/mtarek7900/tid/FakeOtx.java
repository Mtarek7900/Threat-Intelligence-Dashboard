package io.github.mtarek7900.tid;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.ResponseDefinitionBuilder;

/**
 * AlienVault OTX faked at the network edge. It serves the responses in
 * {@code src/test/resources/wiremock/__files/otx}, only to requests carrying the API key. Until a
 * test says otherwise, no pulse mentions any Indicator.
 */
public class FakeOtx {

    public static final String API_KEY = "test-otx-key";

    private static final String INDICATORS = "/otx/api/v1/indicators/";

    private final WireMockServer server;

    FakeOtx(WireMockServer server) {
        this.server = server;
    }

    /** Answers the general section of {@code indicator}, e.g. {@code IPv4/1.2.3.4}, with a recording. */
    public void answers(String indicator, int status, String recording) {
        respond(indicator, aResponse()
                .withStatus(status)
                .withHeader("Content-Type", "application/json")
                .withBodyFile("otx/" + recording));
    }

    /** Answers the general section of {@code indicator} with the given status and body. */
    public void answersWith(String indicator, int status, String body) {
        respond(indicator, aResponse().withStatus(status).withBody(body));
    }

    /** How many requests for the general section of {@code indicator} reached OTX. */
    public int requestsReceived(String indicator) {
        return server.findAll(getRequestedFor(urlPathEqualTo(general(indicator)))).size();
    }

    /** How many requests reached OTX at all. */
    public int requestsReceived() {
        return server.findAll(getRequestedFor(urlPathMatching(INDICATORS + ".*"))).size();
    }

    void mentionsNothing() {
        server.stubFor(get(urlPathMatching(INDICATORS + ".+/general"))
                .atPriority(10)
                .withHeader("X-OTX-API-KEY", equalTo(API_KEY))
                .willReturn(aResponse()
                        .withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBodyFile("otx/ip-address-no-pulses.json")));
    }

    private void respond(String indicator, ResponseDefinitionBuilder response) {
        server.stubFor(get(urlPathEqualTo(general(indicator)))
                .withHeader("X-OTX-API-KEY", equalTo(API_KEY))
                .willReturn(response));
    }

    /** The path as the app sends it, with the colons of an IPv6 address percent-encoded. */
    private static String general(String indicator) {
        return INDICATORS + indicator.replace(":", "%3A") + "/general";
    }
}
