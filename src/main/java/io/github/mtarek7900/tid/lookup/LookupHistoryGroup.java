package io.github.mtarek7900.tid.lookup;

import io.github.mtarek7900.tid.indicator.IndicatorType;
import java.util.List;

/**
 * Every Lookup the Analyst made of one Indicator, most recent first.
 *
 * @param latest the most recent of {@code lookups}
 */
public record LookupHistoryGroup(
        String indicator, IndicatorType indicatorType, int count, LookupHistoryEntry latest, List<LookupHistoryEntry> lookups) {

    static LookupHistoryGroup of(List<LookupHistoryEntry> lookups) {
        var latest = lookups.getFirst();
        return new LookupHistoryGroup(latest.indicator(), latest.indicatorType(), lookups.size(), latest, lookups);
    }
}
