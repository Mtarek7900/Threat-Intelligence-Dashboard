package io.github.mtarek7900.tid.verdict;

import java.util.List;

/**
 * The Verdict and, in the order the Source Results were given, the Reading of each.
 *
 * @param notChecked the Sources whose Source Result is Not Checked
 */
public record Decision(Verdict verdict, List<Reading> readings, List<String> notChecked) {

    /** A Partial Verdict was reached without at least one of the Sources asked. */
    public boolean partial() {
        return !notChecked.isEmpty();
    }
}
