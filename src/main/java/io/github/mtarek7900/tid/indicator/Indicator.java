package io.github.mtarek7900.tid.indicator;

/** An Indicator in its normalised form, with the Indicator Type worked out from the value. */
public record Indicator(String value, IndicatorType type) {}
