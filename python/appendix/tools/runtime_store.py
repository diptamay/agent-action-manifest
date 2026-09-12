"""Single-owner snapshot + event store for the AAM managed Python reference.

SQLite uses WAL/FULL and a POSIX advisory lifetime lock. One live ManagedGate per
store, on a local filesystem; no replica, NFS, rollback-resistance, or exactly-once
remote-effect claim. The protected snapshot contains sensitive lifecycle artifacts.
Only allowlisted audit envelopes are exposed by events(). Never put credentials in
adapter receipts. Transport authentication, encryption/backup/retention are deployment
responsibilities. InMemoryRuntimeStore has the same transaction API, NOT durability.
"""
from __future__ import annotations
import copy
import hashlib
import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Any


def encoded(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)


class AuditUnavailable(RuntimeError):
    """Mandatory local persistence unavailable. Never implies a remote action failed."""


class StoreConflict(AuditUnavailable):
    pass


class InMemoryRuntimeStore:
    durable = False
    def __init__(self):
        self._guard = threading.RLock()
        self._state = None
        self._revision = 0
        self._events = []
        self._binding = None
        self._attached = False
        self._closed = False
        self._cursors = {}
        self._export_lock = threading.Lock()

    def attach(self, binding: dict) -> tuple[int, dict | None]:
        with self._guard:
            self._check()
            if self._attached:
                raise StoreConflict('store already has a live gate owner')
            if self._binding is not None and self._binding != binding:
                raise StoreConflict('store identity/key/policy binding differs; explicit migration required')
            self._binding = copy.deepcopy(binding)
            self._attached = True
            return self._revision, copy.deepcopy(self._state)

    def _check(self):
        if self._closed:
            raise AuditUnavailable('runtime store is closed')

    def commit(self, expected_revision: int, state: dict, events: list[dict]) -> int:
        with self._guard:
            self._check()
            if expected_revision != self._revision:
                raise StoreConflict('runtime state revision changed')
            encoded(state)
            pending = self._envelope(events)
            self._state = copy.deepcopy(state)
            self._events.extend(pending)
            self._revision += 1
            return self._revision

    def _envelope(self, events):
        previous = self._events[-1]['event_hash'] if self._events else None
        seq = len(self._events)
        pending = []
        ids = {e['event_id'] for e in self._events}
        for raw in events:
            e = copy.deepcopy(raw)
            if e['event_id'] in ids:
                raise StoreConflict('duplicate audit event id')
            ids.add(e['event_id'])
            seq += 1
            e.update(sequence=seq, previous_hash=previous, transaction_revision=self._revision+1)
            e['event_hash'] = hashlib.sha256(encoded(e).encode()).hexdigest()
            previous = e['event_hash']
            pending.append(e)
        return pending

    def events(self, after: int = 0, limit: int = 1000) -> list[dict]:
        if type(after) is not int or after < 0 or type(limit) is not int or not 1 <= limit <= 10000:
            raise ValueError('invalid event cursor or limit')
        with self._guard:
            self._check()
            return copy.deepcopy(self._events[after:after+limit])

    def event_count(self) -> int:
        with self._guard:
            self._check()
            return len(self._events)

    def cursor(self, consumer: str) -> int:
        with self._guard:
            self._check()
            return self._cursors.get(consumer, 0)

    def advance(self, consumer: str, expected: int, to: int):
        with self._guard:
            self._check()
            if self._cursors.get(consumer, 0) != expected or not expected <= to <= len(self._events):
                raise StoreConflict('export checkpoint mismatch')
            self._cursors[consumer] = to

    def verify_chain(self) -> bool:
        with self._guard:
            previous = None
            for seq, event in enumerate(self._events, 1):
                body = {k:v for k,v in event.items() if k != 'event_hash'}
                if event['sequence'] != seq or event['previous_hash'] != previous or hashlib.sha256(encoded(body).encode()).hexdigest() != event['event_hash']:
                    return False
                previous = event['event_hash']
            return True

    def close(self):
        with self._guard:
            self._closed = True


class SQLiteRuntimeStore(InMemoryRuntimeStore):
    durable = True
    def __init__(self, path: str | Path):
        super().__init__()
        try:
            import fcntl
        except ImportError as exc:
            raise RuntimeError('SQLiteRuntimeStore requires POSIX flock; Windows is not supported by this adapter') from exc
        self._fcntl = fcntl
        path = Path(path).absolute()
        if path.is_symlink():
            raise ValueError('database path must not be a symlink')
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.path = path
        self._lockfile = None
        self._conn = None
        try:
            flags = os.O_RDWR | os.O_CREAT | getattr(os, 'O_NOFOLLOW', 0)
            fd = os.open(str(path)+'.owner.lock', flags, 0o600)
            self._lockfile = os.fdopen(fd, 'a+b')
            fcntl.flock(self._lockfile.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            fd = os.open(path, flags, 0o600)
            os.close(fd)
            os.chmod(path, 0o600)
            self._conn = sqlite3.connect(str(path), isolation_level=None, check_same_thread=False, timeout=5)
            self._conn.execute('PRAGMA journal_mode=WAL')
            self._conn.execute('PRAGMA synchronous=FULL')
            self._conn.execute('PRAGMA foreign_keys=ON')
            self._conn.executescript('''
                CREATE TABLE IF NOT EXISTS metadata (id INTEGER PRIMARY KEY CHECK(id=1), binding TEXT, revision INTEGER NOT NULL, state TEXT);
                INSERT OR IGNORE INTO metadata VALUES(1,NULL,0,NULL);
                CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY, event_id TEXT UNIQUE NOT NULL, body TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS cursors (consumer TEXT PRIMARY KEY, seq INTEGER NOT NULL);
                CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events BEGIN SELECT RAISE(ABORT,'events are append-only'); END;
                CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events BEGIN SELECT RAISE(ABORT,'events are append-only'); END;
            ''')
            if self._conn.execute('PRAGMA quick_check').fetchone()[0] != 'ok':
                raise AuditUnavailable('database integrity check failed')
            self._load()
            if not self.verify_chain():
                raise AuditUnavailable('audit hash chain invalid')
        except Exception as exc:
            self.close()
            if isinstance(exc, (ValueError, AuditUnavailable)):
                raise
            raise AuditUnavailable('cannot acquire/open runtime store') from exc

    def _load(self):
        binding, revision, state = self._conn.execute('SELECT binding,revision,state FROM metadata WHERE id=1').fetchone()
        self._binding = json.loads(binding) if binding else None
        self._revision = revision
        self._state = json.loads(state) if state else None
        # Bounded reference: loads the complete history. Not an unbounded production store.
        self._events = [json.loads(r[0]) for r in self._conn.execute('SELECT body FROM events ORDER BY seq')]
        self._cursors = dict(self._conn.execute('SELECT consumer,seq FROM cursors'))

    def attach(self, binding: dict):
        with self._guard:
            result = super().attach(binding)
            try:
                self._conn.execute('UPDATE metadata SET binding=? WHERE id=1', (encoded(binding),))
            except sqlite3.Error as exc:
                self._attached = False
                raise AuditUnavailable('runtime binding persistence failed') from exc
            return result

    def commit(self, expected_revision: int, state: dict, events: list[dict]) -> int:
        with self._guard:
            self._check()
            if expected_revision != self._revision:
                raise StoreConflict('runtime state revision changed')
            state_text = encoded(state)
            pending = self._envelope(events)
            try:
                self._conn.execute('BEGIN IMMEDIATE')
                row = self._conn.execute('SELECT revision FROM metadata WHERE id=1').fetchone()
                if row[0] != expected_revision:
                    raise StoreConflict('database runtime revision changed')
                for event in pending:
                    self._conn.execute('INSERT INTO events VALUES(?,?,?)', (event['sequence'],event['event_id'],encoded(event)))
                self._conn.execute('UPDATE metadata SET revision=?,state=? WHERE id=1', (expected_revision+1,state_text))
                self._conn.execute('COMMIT')
            except Exception as exc:
                try:
                    self._conn.execute('ROLLBACK')
                except sqlite3.Error:
                    pass
                if isinstance(exc, AuditUnavailable):
                    raise
                raise AuditUnavailable('runtime transaction did not acknowledge commit; restart and inspect persisted state') from exc
            self._revision += 1
            self._state = copy.deepcopy(state)
            self._events.extend(pending)
            return self._revision

    def advance(self, consumer: str, expected: int, to: int):
        with self._guard:
            self._check()
            if self._cursors.get(consumer,0) != expected or not expected <= to <= len(self._events):
                raise StoreConflict('export checkpoint mismatch')
            try:
                self._conn.execute('INSERT INTO cursors VALUES(?,?) ON CONFLICT(consumer) DO UPDATE SET seq=excluded.seq', (consumer,to))
            except sqlite3.Error as exc:
                raise AuditUnavailable('export checkpoint persistence failed') from exc
            self._cursors[consumer] = to

    def close(self):
        with self._guard:
            if self._conn is not None:
                self._conn.close()
                self._conn = None
            if self._lockfile is not None:
                self._lockfile.close()
                self._lockfile = None
            self._closed = True
