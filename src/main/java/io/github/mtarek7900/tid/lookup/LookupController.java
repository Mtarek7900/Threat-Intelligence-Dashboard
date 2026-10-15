package io.github.mtarek7900.tid.lookup;

import java.util.List;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/lookups")
class LookupController {

    private final LookupHistory history;

    LookupController(LookupHistory history) {
        this.history = history;
    }

    @GetMapping
    List<LookupHistoryEntry> history() {
        return history.of(LocalAnalyst.ID);
    }
}
