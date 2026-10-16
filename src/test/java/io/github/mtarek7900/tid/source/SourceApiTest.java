package io.github.mtarek7900.tid.source;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.time.Clock;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestClient;

class SourceApiTest {

    @Test
    void aSourceWithNoApiKeyIsNotAskedSoDoesntTakeADailyCall() {
        var callsTaken = new AtomicInteger();
        var api = new SourceApi(
                "VirusTotal",
                "VIRUSTOTAL_API_KEY",
                "",
                RestClient.create(),
                new ObjectMapper(),
                () -> callsTaken.incrementAndGet() > 0,
                Clock.systemUTC());

        assertThatThrownBy(() -> api.get(uri -> uri.path("/anything").build()))
                .isInstanceOfSatisfying(
                        SourceException.class,
                        e -> assertThat(e.reason()).isEqualTo(NotCheckedReason.MISSING_API_KEY));
        assertThat(callsTaken).hasValue(0);
    }
}
