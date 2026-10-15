package io.github.mtarek7900.tid.source;

/** A Source didn't give an answer the dashboard can use. */
public class SourceException extends RuntimeException {

    SourceException(String message) {
        super(message);
    }

    SourceException(String message, Throwable cause) {
        super(message, cause);
    }
}
