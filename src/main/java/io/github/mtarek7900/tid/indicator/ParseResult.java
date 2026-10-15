package io.github.mtarek7900.tid.indicator;

/** What {@link IndicatorParser} made of the Analyst's raw input. */
public sealed interface ParseResult {

    record Accepted(Indicator indicator) implements ParseResult {}

    /** The input isn't an Indicator; {@code message} tells the Analyst what's wrong. */
    record Rejected(Rejection reason, String message) implements ParseResult {}

    enum Rejection {
        UNRECOGNISED,
        URL_NOT_SUPPORTED,
        RESERVED_IP_ADDRESS
    }
}
