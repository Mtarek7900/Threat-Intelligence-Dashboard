package io.github.mtarek7900.tid.source;

/** Why a Source Result is Not Checked: the Source wasn't asked or couldn't answer. */
public enum NotCheckedReason {
    TIMEOUT,
    SOURCE_ERROR,
    RATE_LIMITED,
    MISSING_API_KEY
}
