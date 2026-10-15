package io.github.mtarek7900.tid.verdict;

import io.github.mtarek7900.tid.source.SourceResult;

/**
 * The Signal the Verdict rule read from one Source Result, and its "Why?" line.
 *
 * @param counted whether the Verdict counts the Signal; a Corroborating Source's Signal counts only
 *     when another Source also gives one
 */
public record Reading(SourceResult result, Signal signal, boolean counted, String explanation) {

    /** A Reading whose Signal the Verdict counts, as it does for every Source but a Corroborating one. */
    static Reading counted(SourceResult result, Signal signal, String explanation) {
        return new Reading(result, signal, true, explanation);
    }
}
