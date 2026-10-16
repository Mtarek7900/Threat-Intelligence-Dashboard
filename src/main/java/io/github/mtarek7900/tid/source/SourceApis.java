package io.github.mtarek7900.tid.source;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.net.http.HttpClient;
import java.time.Clock;
import java.util.function.BooleanSupplier;
import java.util.function.Consumer;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

/** Makes each Source's {@link SourceApi}, with what every Source's HTTP client has in common. */
@Component
class SourceApis {

    private final RestClient.Builder http;
    private final SourcesProperties sources;
    private final ObjectMapper json;
    private final DailyCalls dailyCalls;
    private final Clock clock;

    SourceApis(
            RestClient.Builder http,
            SourcesProperties sources,
            ObjectMapper json,
            DailyCalls dailyCalls,
            Clock clock) {
        this.http = http;
        this.sources = sources;
        this.json = json;
        this.dailyCalls = dailyCalls;
        this.clock = clock;
    }

    /**
     * @param apiKeyVariable the environment variable that sets {@code apiKey}, named when it isn't set
     * @param dailyQuota how many calls the Source allows a day
     * @param client sets the Source's base URL and how it is given the API key
     */
    SourceApi of(
            String source,
            String apiKeyVariable,
            String apiKey,
            int dailyQuota,
            Consumer<RestClient.Builder> client) {
        // Gives up connecting or waiting for an answer after the timeout, so a call the Lookup has
        // stopped waiting for doesn't hold its connection open forever
        var timeout = sources.timeout();
        var requests = new JdkClientHttpRequestFactory(
                HttpClient.newBuilder().connectTimeout(timeout).build());
        requests.setReadTimeout(timeout);
        var builder = http.clone().requestFactory(requests);
        client.accept(builder);
        // Rounded down, so the Source is never asked more than the stop percentage of its quota
        var dailyLimit = dailyQuota * sources.dailyStopPercent() / 100;
        BooleanSupplier takeCall = () -> dailyCalls.takeCall(source, dailyLimit);
        return new SourceApi(source, apiKeyVariable, apiKey, builder.build(), json, takeCall, clock);
    }
}
