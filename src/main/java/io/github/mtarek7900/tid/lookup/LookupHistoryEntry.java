package io.github.mtarek7900.tid.lookup;

import java.time.Instant;
import java.util.UUID;

public record LookupHistoryEntry(
        UUID id, String indicator, String indicatorType, String verdict, Instant lookedUpAt) {}
