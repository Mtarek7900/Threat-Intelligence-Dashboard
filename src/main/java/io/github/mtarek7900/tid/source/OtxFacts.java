package io.github.mtarek7900.tid.source;

import java.util.List;

/**
 * The AlienVault OTX pulses that mention the Indicator.
 *
 * @param pulseCount how many pulses mention it
 * @param pulses the pulses OTX listed, which can be fewer than {@code pulseCount}
 */
public record OtxFacts(int pulseCount, List<Pulse> pulses) implements SourceFacts {

    @Override
    public boolean fromCorroboratingSource() {
        return true;
    }

    /** A pulse: a collection of Indicators an OTX member published, e.g. for one campaign. */
    public record Pulse(String name, List<String> tags) {}
}
