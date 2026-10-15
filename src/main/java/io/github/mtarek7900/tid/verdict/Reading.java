package io.github.mtarek7900.tid.verdict;

import io.github.mtarek7900.tid.source.SourceResult;

/** The Signal the Verdict rule read from one Source Result, and its "Why?" line. */
public record Reading(SourceResult result, Signal signal, String explanation) {}
