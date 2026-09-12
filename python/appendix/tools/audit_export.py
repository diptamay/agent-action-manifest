"""At-least-once audit delivery, never execution retry. No dependency on Gate.

Call drain() on a service-owned worker/schedule OUTSIDE request admission. Receiver
must deduplicate event_id. A crash after receiver acceptance but before checkpoint
causes replay. The supplied SQLite receiver demonstrates idempotent acceptance.
"""
from __future__ import annotations
import json
import sqlite3
from runtime_store import encoded


def drain(store, consumer, send, *, batch_size=100, max_batches=10):
    if not isinstance(consumer,str) or not consumer or len(consumer)>128:
        raise ValueError('bounded named consumer required')
    if type(max_batches) is not int or not 1 <= max_batches <= 10000:
        raise ValueError('invalid max_batches')
    sent=0
    # One drain at a time per runtime store; send never runs with a gate/DB transaction lock.
    with store._export_lock:
        for _ in range(max_batches):
            position=store.cursor(consumer)
            events=store.events(position,batch_size)
            if not events:
                break
            for event in events:
                if send(event) is not True:
                    raise RuntimeError('audit receiver did not acknowledge acceptance')
                store.advance(consumer,position,event['sequence'])
                position=event['sequence'];sent+=1
    return {'delivered':sent,'checkpoint':store.cursor(consumer),
            'backlog':store.event_count()-store.cursor(consumer)}


class SQLiteAuditReceiver:
    """Local demonstration receiver. Not remote/WORM storage or a SIEM connector."""
    def __init__(self,path):
        import os
        fd=os.open(path,os.O_CREAT|os.O_RDWR|getattr(os,'O_NOFOLLOW',0),0o600);os.close(fd)
        self.conn=sqlite3.connect(path)
        self.conn.execute('PRAGMA synchronous=FULL')
        self.conn.execute('CREATE TABLE IF NOT EXISTS received(event_id TEXT PRIMARY KEY,body TEXT NOT NULL)')
        self.conn.commit()
    def __call__(self,event):
        body=encoded(event)
        old=self.conn.execute('SELECT body FROM received WHERE event_id=?',(event['event_id'],)).fetchone()
        if old and old[0]!=body:
            raise ValueError('same event id with different content')
        self.conn.execute('INSERT OR IGNORE INTO received VALUES(?,?)',(event['event_id'],body))
        self.conn.commit();return True
    def close(self):
        self.conn.close()
