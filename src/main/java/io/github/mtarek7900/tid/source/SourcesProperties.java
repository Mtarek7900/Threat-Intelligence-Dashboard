package io.github.mtarek7900.tid.source;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** {@code tid.sources} in application.yml: settings shared by every Source. */
@ConfigurationProperties("tid.sources")
public record SourcesProperties(Duration timeout) {}
