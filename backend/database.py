"""Two engines on the same SQLite file.

read engine  : BEGIN          (deferred) -> one consistent snapshot per session, never blocks writers (WAL)
write engine : BEGIN IMMEDIATE            -> takes the write lock up front, so "read tip, append block" is atomic
                                             across threads AND processes.

Use `with database.WriteSession.begin() as db:` on a FRESH session for every write.
Never call `.begin()` on a session that has already run a query (SQLAlchemy raises).
"""
from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from .config import settings


class Base(DeclarativeBase):
    pass


engine = write_engine = ReadSession = WriteSession = None


def _make_engine(url: str, begin_sql: str):
    eng = create_engine(url, connect_args={"check_same_thread": False})

    @event.listens_for(eng, "connect")
    def _pragmas(dbapi, _record):
        dbapi.isolation_level = None  # we, not pysqlite, decide when a transaction starts
        cur = dbapi.cursor()
        for p in ("journal_mode=WAL", "synchronous=NORMAL", "foreign_keys=ON", "busy_timeout=5000"):
            cur.execute(f"PRAGMA {p}")
        cur.close()

    @event.listens_for(eng, "begin")
    def _begin(conn):
        conn.exec_driver_sql(begin_sql)

    return eng


def init(url: str | None = None) -> None:
    global engine, write_engine, ReadSession, WriteSession
    from . import models  # noqa: F401  (registers the tables)

    url = url or settings.DATABASE_URL
    engine = _make_engine(url, "BEGIN")
    write_engine = _make_engine(url, "BEGIN IMMEDIATE")
    ReadSession = sessionmaker(bind=engine, expire_on_commit=False)
    WriteSession = sessionmaker(bind=write_engine, expire_on_commit=False)
    Base.metadata.create_all(write_engine)
