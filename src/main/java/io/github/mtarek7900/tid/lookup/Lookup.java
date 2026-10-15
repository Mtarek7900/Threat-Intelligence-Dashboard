package io.github.mtarek7900.tid.lookup;

import io.github.mtarek7900.tid.indicator.IndicatorType;
import java.time.Instant;
import java.util.UUID;

public record Lookup(UUID id, String indicator, IndicatorType indicatorType, Verdict verdict, Instant lookedUpAt) {}
