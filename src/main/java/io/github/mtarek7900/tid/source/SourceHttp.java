package io.github.mtarek7900.tid.source;

import java.net.http.HttpClient;
import java.time.Duration;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.web.client.RestClient;

/** What every Source's HTTP client has in common. */
final class SourceHttp {

    private SourceHttp() {}

    /**
     * Gives up connecting or waiting for an answer after {@code timeout}, so a call the Lookup has
     * stopped waiting for doesn't hold its connection open forever.
     */
    static RestClient.Builder withTimeouts(RestClient.Builder http, Duration timeout) {
        var requests = new JdkClientHttpRequestFactory(
                HttpClient.newBuilder().connectTimeout(timeout).build());
        requests.setReadTimeout(timeout);
        return http.requestFactory(requests);
    }
}
