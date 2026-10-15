package io.github.mtarek7900.tid.lookup;

import io.github.mtarek7900.tid.indicator.IndicatorType;
import io.github.mtarek7900.tid.verdict.Verdict;
import java.time.Instant;
import java.util.UUID;

public record LookupHistoryEntry(
        UUID id, String indicator, IndicatorType indicatorType, Verdict verdict, Instant lookedUpAt) {}
