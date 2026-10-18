# BeerStream1

A MySQL client for asyncio that lives on the event loop. Written in Rust,
built for the request path of [Poltergeist](https://github.com/RealistikGDPS/poltergeist).

Every query costs one `write(2)`, one `read(2)` and one Future. Nothing runs
on another thread, nothing crosses the GIL twice, and the wire protocol is
parsed straight out of the socket buffer into Python objects.

## Why it is fast

- **The socket is registered with the asyncio loop.** The pool calls
  `loop.add_reader` once per connection; the loop calls back into Rust when
  bytes arrive. There is no stream abstraction, no per-packet `await`, no
  background runtime and no cross-thread handoff.
- **One Future per query**, created with `loop.create_future()` and resolved
  from inside the read callback. The awaiting Task resumes with the rows
  already built.
- **Rows are built in Rust.** Column names are interned once per result set;
  each row is a `dict` filled with pre-hashed keys and values converted
  directly from the text protocol.
- **Statements are interpolated client-side** with the same `%(name)s`
  placeholders and escaping rules as PyMySQL, so there is no prepare round
  trip and existing queries run unchanged.

Measured against asyncmy 0.2.14 on the same machine, 32 concurrent tasks,
one row fetched by primary key: 11.5 µs of CPU per query instead of 55.5 µs
and four times the throughput of a single process.

## Usage

```python
import beerstream1

pool = beerstream1.Pool(
    host="127.0.0.1",
    port=3306,
    user="app",
    password="secret",
    database="app",
    min_size=2,
    max_size=16,
    init_command="SET time_zone = '+00:00'",
)
await pool.connect()

rows = await pool.fetch_all("SELECT id, name FROM users WHERE id > %(id)s", {"id": 10})
row = await pool.fetch_one("SELECT * FROM users WHERE id = %(id)s", {"id": 1})
count = await pool.fetch_val("SELECT COUNT(*) FROM users")
result = await pool.execute("INSERT INTO users (name) VALUES (%(name)s)", {"name": "x"})
result.last_row_id, result.affected_rows

transaction = await pool.begin()
try:
    await transaction.execute("UPDATE users SET name = %(n)s WHERE id = %(id)s", {"n": "y", "id": 1})
    await transaction.commit()
except Exception:
    await transaction.rollback()
    raise

await pool.close()
```

Every method returns an asyncio Future, so the calls are awaited like any
coroutine. The pool must be created and used from one event loop; uvloop and
the default loop both work.

### Values

Bound parameters: `None`, `bool`, `int`, `float`, `str`, `bytes`,
`datetime.datetime`, `datetime.date`, `datetime.timedelta` and
`decimal.Decimal`. A `%` in a query with bound parameters is written `%%`;
a query without parameters is sent verbatim.

Result columns follow PyMySQL: integer types become `int`, `FLOAT` and
`DOUBLE` become `float`, `DECIMAL` becomes `decimal.Decimal`, `DATETIME` and
`TIMESTAMP` become naive `datetime.datetime`, `DATE` becomes `datetime.date`,
`TIME` becomes `datetime.timedelta`, binary columns become `bytes`, and
everything else, including `JSON` and `ENUM`, becomes `str`. Zero dates
become `None`.

### Transactions

`pool.begin()` takes a connection out of the pool and returns a `Transaction`
with the same four statement methods plus `commit()` and `rollback()`, either
of which returns the connection. A transaction that is garbage collected
without finishing has its connection discarded, never reused.

### Connections

The pool opens `min_size` connections on `connect()` and grows on demand up to
`max_size`; further queries wait in order. A connection idle for longer than
`max_idle_seconds` is closed and replaced. A connection the server drops fails
the query it was running with `ConnectionLost` and is replaced on the next
query.

Supported authentication: `caching_sha2_password` (fast path and the RSA full
authentication over a plain connection) and `mysql_native_password`. TLS is
not supported; the client is meant for a private network.

### Errors

`beerstream1.Error` is the base. `MySQLError` carries `code`, `sqlstate` and
`message` from the server's error packet. `ProtocolError` means the server
sent something unexpected, `ConnectionLost` that the socket dropped, and
`PoolClosed` that the pool was closed.

## Limits

- One statement per call. Multi-statement text and multiple result sets are
  rejected.
- `LOCAL INFILE` is not supported.
- Host names are resolved synchronously when a connection is opened, which
  happens at startup and after a connection is lost.

## Building

```bash
uv venv && uvx maturin develop --release   # local build into the venv
cargo test                                 # protocol unit tests
```

Wheels for Python 3.14 on manylinux x86_64 and aarch64 are built by the
GitHub workflow and attached to each `v*` release.
