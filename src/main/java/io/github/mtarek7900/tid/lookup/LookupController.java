package io.github.mtarek7900.tid.lookup;

import io.github.mtarek7900.tid.indicator.IndicatorParser;
import io.github.mtarek7900.tid.indicator.ParseResult.Accepted;
import io.github.mtarek7900.tid.indicator.ParseResult.Rejected;
import java.util.List;
import java.util.Objects;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/lookups")
class LookupController {

    private final LookupHistory history;
    private final LookupService lookups;

    LookupController(LookupHistory history, LookupService lookups) {
        this.history = history;
        this.lookups = lookups;
    }

    @GetMapping
    List<LookupHistoryEntry> history() {
        return history.of(LocalAnalyst.ID);
    }

    /** Rejected input gets a 400 problem whose detail tells the Analyst what's wrong. */
    @PostMapping
    ResponseEntity<?> lookUp(@RequestBody LookupRequest request) {
        return switch (IndicatorParser.parse(Objects.requireNonNullElse(request.input(), ""))) {
            case Accepted accepted -> ResponseEntity.status(HttpStatus.CREATED)
                    .body(lookups.lookUp(LocalAnalyst.ID, accepted.indicator(), request.refresh()));
            case Rejected rejected -> {
                var problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, rejected.message());
                problem.setProperty("reason", rejected.reason());
                yield ResponseEntity.of(problem).build();
            }
        };
    }

    /** @param refresh whether to ask every Source again instead of reusing recent Source Results */
    record LookupRequest(String input, boolean refresh) {}
}
