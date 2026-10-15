package io.github.mtarek7900.tid;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.time.Clock;
import java.time.Instant;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.context.annotation.Primary;
import org.springframework.test.context.jdbc.Sql;

/**
 * Seam 1: the whole app on a random port, real HTTP, PostgreSQL in Testcontainers and a
 * {@link TestClock} in place of the system clock. Inject the TestClock to control time. Every
 * test starts with no Lookups, because all integration tests share one database.
 */
@Target(ElementType.TYPE)
@Retention(RetentionPolicy.RUNTIME)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@Import({TestcontainersConfiguration.class, IntegrationTest.TestClockConfiguration.class})
@Sql(statements = "delete from lookup")
public @interface IntegrationTest {

    @TestConfiguration(proxyBeanMethods = false)
    class TestClockConfiguration {

        @Bean
        @Primary
        TestClock testClock() {
            return new TestClock(Instant.parse("2026-01-15T10:00:00Z"));
        }
    }
}
