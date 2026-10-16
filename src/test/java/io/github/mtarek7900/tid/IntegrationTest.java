package io.github.mtarek7900.tid;

import com.github.tomakehurst.wiremock.WireMockServer;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.time.Instant;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.jdbc.Sql;
import org.springframework.test.context.junit.jupiter.SpringExtension;

/**
 * Seam 1: the whole app on a random port, real HTTP, PostgreSQL in Testcontainers, Sources faked
 * by WireMock and a {@link TestClock} in place of the system clock. Inject the TestClock to control
 * time, and {@link FakeVirusTotal}, {@link FakeAbuseIpdb} and {@link FakeOtx} to say what the Sources
 * answer. Every test starts at {@link #START}, with no Lookups, no Source Results and nothing programmed
 * into the fake Sources except that OTX has no pulses, because all integration tests share one
 * database, one clock and one WireMock server. Each Source gets {@link #SOURCE_TIMEOUT} to answer;
 * a test class can override these properties with its own {@code @TestPropertySource}.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import({
    TestcontainersConfiguration.class,
    FakeSourcesConfiguration.class,
    IntegrationTest.TestClockConfiguration.class
})
@TestPropertySource(
        properties = {
            "tid.sources.virustotal.api-key=" + FakeVirusTotal.API_KEY,
            "tid.sources.abuseipdb.api-key=" + FakeAbuseIpdb.API_KEY,
            "tid.sources.otx.api-key=" + FakeOtx.API_KEY,
            "tid.sources.timeout=" + IntegrationTest.SOURCE_TIMEOUT
        })
@Sql(statements = "truncate lookup_source_result, lookup, source_result, source_daily_calls")
@ExtendWith(IntegrationTest.ResetSharedState.class)
public @interface IntegrationTest {

    String SOURCE_TIMEOUT = "2s";

    Instant START = Instant.parse("2026-01-15T10:00:00Z");

    @TestConfiguration(proxyBeanMethods = false)
    class TestClockConfiguration {

        @Bean
        @Primary
        TestClock testClock() {
            return new TestClock(START);
        }
    }

    class ResetSharedState implements BeforeEachCallback {

        @Override
        public void beforeEach(ExtensionContext context) {
            var spring = SpringExtension.getApplicationContext(context);
            spring.getBean(WireMockServer.class).resetAll();
            spring.getBean(FakeOtx.class).mentionsNothing();
            spring.getBean(TestClock.class).setInstant(START);
        }
    }
}
