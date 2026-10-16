package io.github.mtarek7900.tid.source;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * {@code tid.sources} in application.yml: settings shared by every Source.
 *
 * @param timeout how long each Source gets to answer before its Source Result is Not Checked
 * @param reuseWindow how young a Source Result must be to be reused instead of asking its Source again
 * @param dailyStopPercent the share of each Source's daily quota after which it isn't asked again that day
 */
@ConfigurationProperties("tid.sources")
public record SourcesProperties(Duration timeout, Duration reuseWindow, int dailyStopPercent) {}
