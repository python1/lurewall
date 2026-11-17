# SPDX-License-Identifier: AGPL-3.0-only
"""The signal collector: classify each record, keep per-source state, log it.

Events written (all through the signed log's roll-up, so a burst from one
source is one entry with a counter, not one line per request):

- ``attack_signal``: one distinct attack signal from one source;
- ``attack_threshold_met``: the source now shows enough distinct attack
  signals inside the window. This is a fact about signals, not a decision:
  nothing is blocked here;
- ``behavior_signal``: context only;
- ``cross_site``: a request that counts for nothing, and what it would have
  raised;
- ``signal_state_evicted``: a source was dropped at the table's size limit.

No event holds text from a request. A signal is named by its config rule or
pattern family, and the request by its nginx request ID and line hash.
"""

from __future__ import annotations

from dataclasses import dataclass

from lurewall.accesslog import Record
from lurewall.logreader import Sink
from lurewall.signals import Classification, Classifier
from lurewall.sources import SignalTracker, SourceView, source_key


@dataclass(frozen=True)
class Observation:
    record: Record
    classification: Classification
    view: SourceView


class SignalCollector:
    def __init__(self, classifier: Classifier, sink: Sink, tracker: SignalTracker | None = None):
        config = classifier.config
        self._classifier = classifier
        self._sink = sink
        # "is None", not truthiness: an empty tracker has length zero.
        if tracker is None:
            tracker = SignalTracker(
                window_ms=config.window_ms,
                threshold=config.distinct_attack_signals,
                max_sources=config.max_sources,
            )
        self._tracker = tracker

    @property
    def tracker(self) -> SignalTracker:
        return self._tracker

    def handle(self, record: Record) -> Observation:
        result = self._classifier.classify(record)
        source = source_key(record.ip)
        was_met = self._tracker.view(source).threshold_met
        view = self._tracker.observe(record, result)
        where = {"request_id": record.request_id, "line": record.line_sha256}
        if record.stale:
            where["stale"] = True

        if result.cross_site:
            self._sink.append(
                "cross_site",
                source,
                {
                    **where,
                    "reason": result.cross_site,
                    "canary": result.canary.canary.id if result.canary else None,
                    "would_raise": sorted({signal.key for signal in result.suppressed}),
                },
                rollup_key=result.cross_site,
            )
        for signal in result.attack:
            self._sink.append(
                "attack_signal",
                source,
                {**where, "signal": signal.key, "form": signal.form},
                rollup_key=signal.key,
            )
        if view.threshold_met and not was_met:
            self._sink.append(
                "attack_threshold_met",
                source,
                {
                    **where,
                    "signals": list(view.attack_keys),
                    "normal_browsing": view.normal_browsing,
                },
            )
        for signal in (*result.behavior, *view.behavior):
            self._sink.append(
                "behavior_signal", source, {**where, "signal": signal.key}, rollup_key=signal.key
            )
        for _ in range(self._tracker.take_evictions()):
            # No source is named: the roll-up counts every drop in one entry.
            self._sink.append("signal_state_evicted", None, {}, rollup_key="")
        return Observation(record=record, classification=result, view=view)
