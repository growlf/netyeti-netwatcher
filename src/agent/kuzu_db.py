"""
Singleton KuzuDB database handle.

KuzuDB only permits a single :class:`kuzu.Database` instance per database
path within a process (it acquires an exclusive file lock).  Any attempt to
open a second ``Database`` object on the same path — even from a different
thread — raises::

    IO exception: Could not set lock on file : /data/netwatch.kuzu/.lock

This module owns the one-and-only ``kuzu.Database`` handle and exposes it via
:func:`get_db`.  All other modules (``kuzu_loader``, ``kuzu_tool``, …) must
obtain their connections through :func:`get_connection` or :func:`get_db`
rather than creating their own ``kuzu.Database`` instances.
"""
import logging
import os
import threading

import kuzu

import config

logger = logging.getLogger(__name__)

_lock = threading.Lock()
_db: kuzu.Database | None = None


def get_db() -> kuzu.Database:
    """Return the shared :class:`kuzu.Database` instance, creating it lazily."""
    global _db
    with _lock:
        if _db is None:
            db_dir = os.path.dirname(config.DB_PATH)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
            logger.info("[KuzuDB] Opening database at %s", config.DB_PATH)
            _db = kuzu.Database(config.DB_PATH)
    return _db


def get_connection() -> kuzu.Connection:
    """Return a new :class:`kuzu.Connection` on the shared database.

    Callers are responsible for closing the connection when done.
    """
    return kuzu.Connection(get_db())
