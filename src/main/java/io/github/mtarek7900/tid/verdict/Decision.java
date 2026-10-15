package io.github.mtarek7900.tid.verdict;

import java.util.List;

/** The Verdict and, in the order the Source Results were given, the Reading of each. */
public record Decision(Verdict verdict, List<Reading> readings) {}
