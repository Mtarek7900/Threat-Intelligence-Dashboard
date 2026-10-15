package io.github.mtarek7900.tid;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

/** A Clock that tests set and advance by hand. */
public class TestClock extends Clock {

    private Instant now;

    public TestClock(Instant now) {
        this.now = now;
    }

    public void setInstant(Instant now) {
        this.now = now;
    }

    public void advance(Duration duration) {
        now = now.plus(duration);
    }

    @Override
    public Instant instant() {
        return now;
    }

    @Override
    public ZoneId getZone() {
        return ZoneOffset.UTC;
    }

    @Override
    public Clock withZone(ZoneId zone) {
        throw new UnsupportedOperationException("The app reads time in UTC only");
    }
}
