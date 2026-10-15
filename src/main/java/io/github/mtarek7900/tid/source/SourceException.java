package io.github.mtarek7900.tid.source;

/** A Source wasn't asked or didn't give an answer the dashboard can use. */
public class SourceException extends RuntimeException {

    private final NotCheckedReason reason;

    SourceException(NotCheckedReason reason, String message) {
        this(reason, message, null);
    }

    SourceException(NotCheckedReason reason, String message, Throwable cause) {
        super(message, cause);
        this.reason = reason;
    }

    public NotCheckedReason reason() {
        return reason;
    }
}
