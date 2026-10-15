package io.github.mtarek7900.tid;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.http.MediaType;
import org.springframework.web.client.RestClient;

@IntegrationTest
class FrontendPackagingTest {

    @LocalServerPort
    int port;

    @Test
    void theAppServesTheReactHomePageFromTheSameOriginAsTheApi() {
        var response = RestClient.create("http://localhost:" + port)
                .get()
                .uri("/")
                .retrieve()
                .toEntity(String.class);

        assertThat(response.getHeaders().getContentType().isCompatibleWith(MediaType.TEXT_HTML))
                .isTrue();
        assertThat(response.getBody())
                .contains("<title>Threat Intelligence Dashboard</title>")
                .contains("<div id=\"root\"></div>");
    }
}
