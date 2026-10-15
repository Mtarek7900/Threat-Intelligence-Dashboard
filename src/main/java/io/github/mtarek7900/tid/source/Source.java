package io.github.mtarek7900.tid.source;

import io.github.mtarek7900.tid.indicator.Indicator;
import io.github.mtarek7900.tid.indicator.IndicatorType;
import java.util.Set;

/** An external threat-intelligence service. Each one is a Spring bean, so adding a Source adds a bean. */
public interface Source {

    /** The name the Analyst sees, e.g. "VirusTotal". */
    String name();

    /** The Indicator Types this Source is asked about. */
    Set<IndicatorType> indicatorTypes();

    /** The Indicator's page on the Source's own site. */
    String link(Indicator indicator);

    /**
     * Asks the Source about the Indicator.
     *
     * @throws SourceException if the Source wasn't asked or didn't give a usable answer
     */
    SourceResult fetch(Indicator indicator);
}
