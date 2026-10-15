package io.github.mtarek7900.tid;

import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

import com.github.tomakehurst.wiremock.WireMockServer;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.DynamicPropertyRegistrar;

/** Points every Source at one WireMock server, which tests program through {@link FakeVirusTotal} and {@link FakeAbuseIpdb}. */
@TestConfiguration(proxyBeanMethods = false)
public class FakeSourcesConfiguration {

    @Bean(destroyMethod = "stop")
    WireMockServer fakeSources() {
        var server = new WireMockServer(options().dynamicPort().usingFilesUnderClasspath("wiremock"));
        server.start();
        return server;
    }

    @Bean
    FakeVirusTotal fakeVirusTotal(WireMockServer fakeSources) {
        return new FakeVirusTotal(fakeSources);
    }

    @Bean
    FakeAbuseIpdb fakeAbuseIpdb(WireMockServer fakeSources) {
        return new FakeAbuseIpdb(fakeSources);
    }

    @Bean
    DynamicPropertyRegistrar fakeSourceProperties(WireMockServer fakeSources) {
        return registry -> {
            registry.add("tid.sources.virustotal.base-url", fakeSources::baseUrl);
            registry.add("tid.sources.abuseipdb.base-url", () -> fakeSources.baseUrl() + "/abuseipdb");
        };
    }
}
