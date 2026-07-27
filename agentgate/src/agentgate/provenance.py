"""Provenance: a tamper-evident, append-only record of every decision.

Each entry stores the action, the final decision, and the SHA-256 hash of the
previous entry. Any modification to a past entry breaks the chain, which
``verify()`` detects. This is the "prove what the agent did, and that the log
wasn't edited after the fact" property that auditors and incident responders
need — and it's the seed of the paid audit/compliance layer.

The skeleton persists to a JSON-lines file. A production build would push to
an append-only store or a transparency log; the interface stays the same.
"""

from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .action import Action
from .decision import Decision

GENESIS = "0" * 64


def _hash(payload: str) -> str:
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass
class Entry:
    action_id: str
    summary: str
    tool: str
    agent_id: str
    principal: str
    effect: str
    reason: str
    policy: str
    ts: float = field(default_factory=time.time)
    prev_hash: str = GENESIS
    hash: str = ""

    def compute_hash(self) -> str:
        body = {k: v for k, v in asdict(self).items() if k != "hash"}
        return _hash(json.dumps(body, sort_keys=True))


class ProvenanceLog:
    def __init__(self, path: str | Path | None = None):
        self._entries: list[Entry] = []
        self._path = Path(path) if path else None
        if self._path and self._path.exists():
            self._load()

    @property
    def last_hash(self) -> str:
        return self._entries[-1].hash if self._entries else GENESIS

    def record(self, action: Action, decision: Decision) -> Entry:
        entry = Entry(
            action_id=action.id,
            summary=action.summary(),
            tool=action.tool,
            agent_id=action.agent_id,
            principal=action.principal,
            effect=decision.effect.name,
            reason=decision.reason,
            policy=decision.policy,
            prev_hash=self.last_hash,
        )
        entry.hash = entry.compute_hash()
        self._entries.append(entry)
        if self._path:
            with self._path.open("a") as fh:
                fh.write(json.dumps(asdict(entry)) + "\n")
        return entry

    def verify(self) -> bool:
        """Return True iff the chain is intact and unmodified."""
        prev = GENESIS
        for entry in self._entries:
            if entry.prev_hash != prev:
                return False
            if entry.hash != entry.compute_hash():
                return False
            prev = entry.hash
        return True

    def __len__(self) -> int:
        return len(self._entries)

    def __iter__(self):
        return iter(self._entries)

    def _load(self) -> None:
        assert self._path is not None
        for line in self._path.read_text().splitlines():
            if line.strip():
                self._entries.append(Entry(**json.loads(line)))
