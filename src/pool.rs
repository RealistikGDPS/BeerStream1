//! The pool and its connections. Everything runs on the asyncio event loop
//! thread: sockets are non-blocking file descriptors registered with the
//! loop's reader and writer callbacks, and every call returns a loop Future
//! that is resolved from inside those callbacks.

use std::collections::HashMap;
use std::collections::VecDeque;
use std::net::ToSocketAddrs;
use std::time::Instant;

use pyo3::exceptions::PyRuntimeError;
use pyo3::prelude::*;
use pyo3::types::PyDict;
use pyo3::types::PyList;
use pyo3::types::PyString;

use crate::convert;
use crate::convert::Kind;
use crate::errors;
use crate::escape;
use crate::protocol as proto;
use crate::protocol::Reader;

const READ_CHUNK: usize = 64 * 1024;

#[pyclass(frozen, get_all, module = "beerstream1")]
#[derive(Clone)]
pub struct ExecuteResult {
    pub last_row_id: u64,
    pub affected_rows: u64,
}

#[pymethods]
impl ExecuteResult {
    fn __repr__(&self) -> String {
        format!(
            "ExecuteResult(last_row_id={}, affected_rows={})",
            self.last_row_id, self.affected_rows
        )
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    FetchAll,
    FetchOne,
    FetchVal,
    Execute,
    Begin,
    Release,
    Internal,
}

struct Config {
    host: String,
    port: u16,
    user: Vec<u8>,
    password: Vec<u8>,
    database: Vec<u8>,
    min_size: usize,
    max_size: usize,
    init: Vec<Vec<u8>>,
    max_idle: f64,
}

struct Loop {
    create_future: Py<PyAny>,
    add_reader: Py<PyAny>,
    remove_reader: Py<PyAny>,
    add_writer: Py<PyAny>,
    remove_writer: Py<PyAny>,
    call_soon: Py<PyAny>,
    on_readable: Py<PyAny>,
    on_writable: Py<PyAny>,
    poison: Py<PyAny>,
    future_done: Py<PyAny>,
    future_set_result: Py<PyAny>,
    future_set_exception: Py<PyAny>,
}

impl Loop {
    fn new_future(&self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        Ok(self.create_future.bind(py).call0()?.unbind())
    }

    fn resolve(&self, py: Python<'_>, future: &Py<PyAny>, value: Bound<'_, PyAny>) -> PyResult<()> {
        let future = future.bind(py);
        if !self.future_done.bind(py).call1((future,))?.is_truthy()? {
            self.future_set_result.bind(py).call1((future, value))?;
        }
        Ok(())
    }

    fn reject(&self, py: Python<'_>, future: &Py<PyAny>, error: PyErr) -> PyResult<()> {
        let future = future.bind(py);
        if !self.future_done.bind(py).call1((future,))?.is_truthy()? {
            self.future_set_exception
                .bind(py)
                .call1((future, error.into_value(py)))?;
        }
        Ok(())
    }

    fn done_future(&self, py: Python<'_>, value: Bound<'_, PyAny>) -> PyResult<Py<PyAny>> {
        let future = self.new_future(py)?;
        self.resolve(py, &future, value)?;
        Ok(future)
    }

    fn failed_future(&self, py: Python<'_>, error: PyErr) -> PyResult<Py<PyAny>> {
        let future = self.new_future(py)?;
        self.reject(py, &future, error)?;
        Ok(future)
    }
}

struct Job {
    packet: Vec<u8>,
    mode: Mode,
    future: Py<PyAny>,
}

enum ResultStage {
    Header,
    Columns { expected: usize },
    Rows,
}

struct Active {
    mode: Mode,
    future: Py<PyAny>,
    stage: ResultStage,
    kinds: Vec<(Kind, u16)>,
    keys: Vec<Py<PyString>>,
    rows: Option<Py<PyList>>,
    first: Option<Py<PyAny>>,
    seen_rows: u64,
}

enum Stage {
    Connecting,
    AwaitHandshake,
    AwaitAuth,
    AwaitPublicKey,
    Init,
    Idle,
    Busy(Active),
}

/// What the pool has to do after a packet was handled.
enum Completion {
    Ready,
    Done {
        future: Py<PyAny>,
        mode: Mode,
        outcome: Result<Done, PyErr>,
    },
    Fatal(PyErr),
}

enum Done {
    Value(Py<PyAny>),
    Nothing,
}

struct Io {
    fd: i32,
    inbuf: Vec<u8>,
    rpos: usize,
    outbuf: Vec<u8>,
    opos: usize,
    writer_on: bool,
    reader_on: bool,
    big: Vec<u8>,
}

struct State {
    stage: Stage,
    seq: u8,
    nonce: Vec<u8>,
    plugin: String,
    init_queue: VecDeque<Vec<u8>>,
    outgoing: Vec<Vec<u8>>,
    held: bool,
    last_used: Instant,
    generation: u64,
}

struct Conn {
    io: Io,
    st: State,
}

impl Io {
    /// The bounds of the next complete packet payload, if one is buffered.
    fn next_packet(&mut self) -> Option<(usize, usize, u8)> {
        let available = self.inbuf.len() - self.rpos;
        if available < 4 {
            return None;
        }
        let header = &self.inbuf[self.rpos..self.rpos + 4];
        let length = header[0] as usize | (header[1] as usize) << 8 | (header[2] as usize) << 16;
        if available < 4 + length {
            if self.inbuf.capacity() - self.rpos < 4 + length {
                self.inbuf.reserve(4 + length - (self.inbuf.len() - self.rpos));
            }
            return None;
        }
        let start = self.rpos + 4;
        self.rpos = start + length;
        Some((start, start + length, header[3]))
    }

    fn compact(&mut self) {
        if self.rpos == self.inbuf.len() {
            self.inbuf.clear();
            self.rpos = 0;
        } else if self.rpos > READ_CHUNK {
            self.inbuf.drain(..self.rpos);
            self.rpos = 0;
        }
    }
}

#[pyclass(unsendable, module = "beerstream1")]
pub struct Pool {
    config: Config,
    event_loop: Option<Loop>,
    conns: Vec<Option<Conn>>,
    by_fd: HashMap<i32, usize>,
    idle: Vec<usize>,
    pending: VecDeque<Job>,
    closed: bool,
    me: Option<Py<Pool>>,
    startup: Option<(Py<PyAny>, usize)>,
    next_generation: u64,
}

#[pymethods]
impl Pool {
    #[new]
    #[pyo3(signature = (*, host, port=3306, user, password=String::new(), database=String::new(), min_size=1, max_size=10, autocommit=true, init_command=None, max_idle_seconds=300.0))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        host: String,
        port: u16,
        user: String,
        password: String,
        database: String,
        min_size: usize,
        max_size: usize,
        autocommit: bool,
        init_command: Option<String>,
        max_idle_seconds: f64,
    ) -> PyResult<Self> {
        if max_size == 0 || min_size > max_size {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "pool sizes must satisfy 0 < min_size <= max_size",
            ));
        }
        let mut init = vec![format!("SET autocommit = {}", autocommit as u8).into_bytes()];
        if let Some(command) = init_command {
            init.push(command.into_bytes());
        }
        Ok(Pool {
            config: Config {
                host,
                port,
                user: user.into_bytes(),
                password: password.into_bytes(),
                database: database.into_bytes(),
                min_size,
                max_size,
                init,
                max_idle: max_idle_seconds,
            },
            event_loop: None,
            conns: Vec::new(),
            by_fd: HashMap::new(),
            idle: Vec::new(),
            pending: VecDeque::new(),
            closed: false,
            me: None,
            startup: None,
            next_generation: 1,
        })
    }

    /// Opens `min_size` connections. The returned Future resolves once they
    /// are all authenticated, or fails with the first error.
    fn connect(slf: &Bound<'_, Self>, py: Python<'_>) -> PyResult<Py<PyAny>> {
        let mut pool = slf.borrow_mut();
        if pool.event_loop.is_none() {
            pool.attach_loop(py, slf)?;
        }
        pool.closed = false;
        let future = pool.event_loop().new_future(py)?;
        let count = pool.config.min_size;
        if count == 0 {
            pool.event_loop()
                .resolve(py, &future, py.None().into_bound(py).into_any())?;
            return Ok(future);
        }
        pool.startup = Some((future.clone_ref(py), count));
        for _ in 0..count {
            if let Err(error) = pool.open(py) {
                pool.startup = None;
                pool.event_loop().reject(py, &future, error)?;
                break;
            }
        }
        Ok(future)
    }

    fn close(&mut self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.closed = true;
        let error = errors::pool_closed();
        while let Some(job) = self.pending.pop_front() {
            self.event_loop().reject(py, &job.future, error.clone_ref(py))?;
        }
        for index in 0..self.conns.len() {
            if self.conns[index].is_some() {
                self.quit(py, index)?;
            }
        }
        self.event_loop()
            .done_future(py, py.None().into_bound(py).into_any())
    }

    #[pyo3(signature = (sql, params=None))]
    fn fetch_all(
        &mut self,
        py: Python<'_>,
        sql: &str,
        params: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        self.submit(py, sql, params, Mode::FetchAll)
    }

    #[pyo3(signature = (sql, params=None))]
    fn fetch_one(
        &mut self,
        py: Python<'_>,
        sql: &str,
        params: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        self.submit(py, sql, params, Mode::FetchOne)
    }

    #[pyo3(signature = (sql, params=None))]
    fn fetch_val(
        &mut self,
        py: Python<'_>,
        sql: &str,
        params: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        self.submit(py, sql, params, Mode::FetchVal)
    }

    #[pyo3(signature = (sql, params=None))]
    fn execute(
        &mut self,
        py: Python<'_>,
        sql: &str,
        params: Option<&Bound<'_, PyAny>>,
    ) -> PyResult<Py<PyAny>> {
        self.submit(py, sql, params, Mode::Execute)
    }

    /// Takes a connection out of the pool and starts a transaction on it.
    /// Resolves with a `Transaction`.
    fn begin(&mut self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.submit(py, "BEGIN", None, Mode::Begin)
    }

    #[getter]
    fn size(&self) -> usize {
        self.conns.iter().filter(|conn| conn.is_some()).count()
    }

    #[getter]
    fn idle_size(&self) -> usize {
        self.idle.len()
    }

    #[getter]
    fn waiting(&self) -> usize {
        self.pending.len()
    }

    fn _on_readable(&mut self, py: Python<'_>, fd: i32) -> PyResult<()> {
        let Some(&index) = self.by_fd.get(&fd) else {
            return Ok(());
        };
        let mut completions = Vec::new();
        let mut lost: Option<PyErr> = None;
        {
            let conn = self.conns[index]
                .as_mut()
                .expect("registered fd has a connection");
            loop {
                let io = &mut conn.io;
                if io.inbuf.capacity() - io.inbuf.len() < READ_CHUNK {
                    io.inbuf.reserve(READ_CHUNK);
                }
                let spare = io.inbuf.capacity() - io.inbuf.len();
                let read = unsafe {
                    libc::read(
                        io.fd,
                        io.inbuf.as_mut_ptr().add(io.inbuf.len()) as *mut libc::c_void,
                        spare,
                    )
                };
                if read < 0 {
                    let error = std::io::Error::last_os_error();
                    match error.raw_os_error() {
                        Some(libc::EAGAIN) => break,
                        Some(libc::EINTR) => continue,
                        _ => {
                            lost = Some(errors::connection_lost(&error.to_string()));
                            break;
                        }
                    }
                }
                if read == 0 {
                    lost = Some(errors::connection_lost("the server closed the connection"));
                    break;
                }
                unsafe { io.inbuf.set_len(io.inbuf.len() + read as usize) };
                while let Some((start, end, seq)) = conn.io.next_packet() {
                    conn.st.seq = seq.wrapping_add(1);
                    let length = end - start;
                    let outcome = if length == proto::MAX_PAYLOAD {
                        conn.io.big.extend_from_slice(&conn.io.inbuf[start..end]);
                        None
                    } else if !conn.io.big.is_empty() {
                        let mut payload = std::mem::take(&mut conn.io.big);
                        payload.extend_from_slice(&conn.io.inbuf[start..end]);
                        let outcome = conn.st.process(py, &payload, &self.config);
                        payload.clear();
                        conn.io.big = payload;
                        outcome
                    } else {
                        conn.st.process(py, &conn.io.inbuf[start..end], &self.config)
                    };
                    match outcome {
                        None => {}
                        Some(Completion::Fatal(error)) => {
                            lost = Some(error);
                            break;
                        }
                        Some(completion) => completions.push(completion),
                    }
                }
                conn.io.compact();
                if lost.is_some() || (read as usize) < spare {
                    break;
                }
            }
        }
        let outgoing =
            std::mem::take(&mut self.conns[index].as_mut().expect("connection exists").st.outgoing);
        for packet in outgoing {
            if self.conns[index].is_none() {
                break;
            }
            self.send(py, index, &packet)?;
        }
        for completion in completions {
            self.complete(py, index, completion)?;
        }
        if let Some(error) = lost {
            self.drop_conn(py, index, error)?;
        }
        self.flush_pending_writes(py, index)?;
        self.dispatch(py)
    }

    fn _on_writable(&mut self, py: Python<'_>, fd: i32) -> PyResult<()> {
        let Some(&index) = self.by_fd.get(&fd) else {
            return Ok(());
        };
        let connecting = matches!(
            self.conns[index].as_ref().map(|conn| &conn.st.stage),
            Some(Stage::Connecting)
        );
        if connecting {
            let mut error: libc::c_int = 0;
            let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
            let rc = unsafe {
                libc::getsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_ERROR,
                    &mut error as *mut _ as *mut libc::c_void,
                    &mut length,
                )
            };
            if rc != 0 || error != 0 {
                let message = std::io::Error::from_raw_os_error(if rc != 0 {
                    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
                } else {
                    error
                })
                .to_string();
                return self.drop_conn(
                    py,
                    index,
                    errors::connection_lost(&format!("connect failed: {message}")),
                );
            }
            self.set_writer(py, index, false)?;
            self.set_reader(py, index, true)?;
            let conn = self.conns[index].as_mut().expect("connecting connection");
            conn.st.stage = Stage::AwaitHandshake;
            return Ok(());
        }
        self.flush_pending_writes(py, index)
    }

    fn _poison(&mut self, py: Python<'_>, index: usize, generation: u64) -> PyResult<()> {
        self.poison(py, index, generation)
    }
}

impl Pool {
    fn event_loop(&self) -> &Loop {
        self.event_loop.as_ref().expect("pool used before connect()")
    }

    fn attach_loop(&mut self, py: Python<'_>, slf: &Bound<'_, Self>) -> PyResult<()> {
        let asyncio = py.import("asyncio")?;
        let event_loop = asyncio.call_method0("get_running_loop")?;
        let future_type = asyncio.getattr("Future")?;
        self.event_loop = Some(Loop {
            create_future: event_loop.getattr("create_future")?.unbind(),
            add_reader: event_loop.getattr("add_reader")?.unbind(),
            remove_reader: event_loop.getattr("remove_reader")?.unbind(),
            add_writer: event_loop.getattr("add_writer")?.unbind(),
            remove_writer: event_loop.getattr("remove_writer")?.unbind(),
            call_soon: event_loop.getattr("call_soon")?.unbind(),
            on_readable: slf.getattr("_on_readable")?.unbind(),
            on_writable: slf.getattr("_on_writable")?.unbind(),
            poison: slf.getattr("_poison")?.unbind(),
            future_done: future_type.getattr("done")?.unbind(),
            future_set_result: future_type.getattr("set_result")?.unbind(),
            future_set_exception: future_type.getattr("set_exception")?.unbind(),
        });
        self.me = Some(slf.clone().unbind());
        Ok(())
    }

    fn submit(
        &mut self,
        py: Python<'_>,
        sql: &str,
        params: Option<&Bound<'_, PyAny>>,
        mode: Mode,
    ) -> PyResult<Py<PyAny>> {
        if self.event_loop.is_none() {
            return Err(PyRuntimeError::new_err("Pool.connect() has not been awaited"));
        }
        if self.closed {
            return self.event_loop().failed_future(py, errors::pool_closed());
        }
        let packet = match build_query(py, sql, params) {
            Ok(packet) => packet,
            Err(error) => return self.event_loop().failed_future(py, error),
        };
        let future = self.event_loop().new_future(py)?;
        self.pending.push_back(Job {
            packet,
            mode,
            future: future.clone_ref(py),
        });
        self.dispatch(py)?;
        Ok(future)
    }

    /// Runs a statement on the connection a transaction holds.
    pub fn run_held(
        &mut self,
        py: Python<'_>,
        index: usize,
        generation: u64,
        sql: &str,
        params: Option<&Bound<'_, PyAny>>,
        mode: Mode,
    ) -> PyResult<Py<PyAny>> {
        let event_loop = self
            .event_loop
            .as_ref()
            .ok_or_else(|| PyRuntimeError::new_err("pool is not connected"))?;
        let Some(conn) = self.conns.get(index).and_then(|slot| slot.as_ref()) else {
            return event_loop.failed_future(
                py,
                errors::connection_lost("the transaction's connection was lost"),
            );
        };
        if conn.st.generation != generation || !conn.st.held {
            return event_loop.failed_future(
                py,
                errors::connection_lost("the transaction's connection was lost"),
            );
        }
        if !matches!(conn.st.stage, Stage::Idle) {
            return event_loop.failed_future(
                py,
                PyRuntimeError::new_err("a transaction runs one statement at a time"),
            );
        }
        let packet = match build_query(py, sql, params) {
            Ok(packet) => packet,
            Err(error) => return event_loop.failed_future(py, error),
        };
        let future = event_loop.new_future(py)?;
        self.start_job(
            py,
            index,
            Job {
                packet,
                mode,
                future: future.clone_ref(py),
            },
        )?;
        Ok(future)
    }

    /// A transaction object went away without commit or rollback: the
    /// connection's state is unknown, so it is discarded.
    pub fn poison(&mut self, py: Python<'_>, index: usize, generation: u64) -> PyResult<()> {
        let live = self
            .conns
            .get(index)
            .and_then(|slot| slot.as_ref())
            .map(|conn| conn.st.generation == generation && conn.st.held)
            .unwrap_or(false);
        if live {
            self.drop_conn(py, index, errors::connection_lost("transaction abandoned"))?;
            self.dispatch(py)?;
        }
        Ok(())
    }

    fn dispatch(&mut self, py: Python<'_>) -> PyResult<()> {
        while !self.pending.is_empty() {
            let Some(index) = self.idle.pop() else {
                break;
            };
            let stale = self.conns[index]
                .as_ref()
                .map(|conn| conn.st.last_used.elapsed().as_secs_f64() > self.config.max_idle)
                .unwrap_or(true);
            if stale {
                if self.conns[index].is_some() {
                    self.quit(py, index)?;
                }
                continue;
            }
            let job = self.pending.pop_front().expect("checked non-empty");
            self.start_job(py, index, job)?;
        }
        if !self.pending.is_empty() && !self.closed && self.size_including_opening() < self.config.max_size {
            self.open(py)?;
        }
        Ok(())
    }

    fn size_including_opening(&self) -> usize {
        self.conns.iter().filter(|conn| conn.is_some()).count()
    }

    fn start_job(&mut self, py: Python<'_>, index: usize, job: Job) -> PyResult<()> {
        let conn = self.conns[index].as_mut().expect("idle connection exists");
        conn.st.stage = Stage::Busy(Active {
            mode: job.mode,
            future: job.future,
            stage: ResultStage::Header,
            kinds: Vec::new(),
            keys: Vec::new(),
            rows: None,
            first: None,
            seen_rows: 0,
        });
        conn.st.last_used = Instant::now();
        conn.st.seq = 0;
        self.send(py, index, &job.packet)
    }

    fn open(&mut self, py: Python<'_>) -> PyResult<()> {
        let address = (self.config.host.as_str(), self.config.port)
            .to_socket_addrs()
            .map_err(|error| {
                errors::connection_lost(&format!("cannot resolve {}: {error}", self.config.host))
            })?
            .next()
            .ok_or_else(|| errors::connection_lost(&format!("{} has no addresses", self.config.host)))?;
        let domain = socket2::Domain::for_address(address);
        let socket = socket2::Socket::new(domain, socket2::Type::STREAM, None)
            .map_err(|error| errors::connection_lost(&error.to_string()))?;
        socket
            .set_nonblocking(true)
            .map_err(|error| errors::connection_lost(&error.to_string()))?;
        let _ = socket.set_tcp_nodelay(true);
        let _ = socket.set_keepalive(true);
        let connected = match socket.connect(&address.into()) {
            Ok(()) => true,
            Err(error) if error.raw_os_error() == Some(libc::EINPROGRESS) => false,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(error) => return Err(errors::connection_lost(&format!("connect failed: {error}"))),
        };
        use std::os::fd::IntoRawFd;
        let fd = socket.into_raw_fd();
        let generation = self.next_generation;
        self.next_generation += 1;
        let conn = Conn {
            io: Io {
                fd,
                inbuf: Vec::with_capacity(READ_CHUNK),
                rpos: 0,
                outbuf: Vec::new(),
                opos: 0,
                writer_on: false,
                reader_on: false,
                big: Vec::new(),
            },
            st: State {
                stage: if connected {
                    Stage::AwaitHandshake
                } else {
                    Stage::Connecting
                },
                seq: 0,
                nonce: Vec::new(),
                plugin: String::new(),
                init_queue: self.config.init.iter().cloned().collect(),
                outgoing: Vec::new(),
                held: false,
                last_used: Instant::now(),
                generation,
            },
        };
        let index = match self.conns.iter().position(|slot| slot.is_none()) {
            Some(index) => {
                self.conns[index] = Some(conn);
                index
            }
            None => {
                self.conns.push(Some(conn));
                self.conns.len() - 1
            }
        };
        self.by_fd.insert(fd, index);
        if connected {
            self.set_reader(py, index, true)
        } else {
            self.set_writer(py, index, true)
        }
    }

    fn set_reader(&mut self, py: Python<'_>, index: usize, on: bool) -> PyResult<()> {
        let event_loop = self.event_loop.as_ref().expect("pool used before connect()");
        let conn = self.conns[index].as_mut().expect("connection exists");
        if conn.io.reader_on == on {
            return Ok(());
        }
        conn.io.reader_on = on;
        if on {
            event_loop
                .add_reader
                .bind(py)
                .call1((conn.io.fd, &event_loop.on_readable, conn.io.fd))?;
        } else {
            event_loop.remove_reader.bind(py).call1((conn.io.fd,))?;
        }
        Ok(())
    }

    fn set_writer(&mut self, py: Python<'_>, index: usize, on: bool) -> PyResult<()> {
        let event_loop = self.event_loop.as_ref().expect("pool used before connect()");
        let conn = self.conns[index].as_mut().expect("connection exists");
        if conn.io.writer_on == on {
            return Ok(());
        }
        conn.io.writer_on = on;
        if on {
            event_loop
                .add_writer
                .bind(py)
                .call1((conn.io.fd, &event_loop.on_writable, conn.io.fd))?;
        } else {
            event_loop.remove_writer.bind(py).call1((conn.io.fd,))?;
        }
        Ok(())
    }

    /// Writes as much as the socket takes now and buffers the rest.
    fn send(&mut self, py: Python<'_>, index: usize, bytes: &[u8]) -> PyResult<()> {
        let conn = self.conns[index].as_mut().expect("connection exists");
        let io = &mut conn.io;
        if io.opos < io.outbuf.len() {
            io.outbuf.extend_from_slice(bytes);
            return Ok(());
        }
        let mut written = 0;
        while written < bytes.len() {
            let rc = unsafe {
                libc::write(
                    io.fd,
                    bytes[written..].as_ptr() as *const libc::c_void,
                    bytes.len() - written,
                )
            };
            if rc < 0 {
                let error = std::io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::EAGAIN) => break,
                    Some(libc::EINTR) => continue,
                    _ => return self.drop_conn(py, index, errors::connection_lost(&error.to_string())),
                }
            }
            written += rc as usize;
        }
        if written < bytes.len() {
            io.outbuf.clear();
            io.opos = 0;
            io.outbuf.extend_from_slice(&bytes[written..]);
            self.set_writer(py, index, true)?;
        }
        Ok(())
    }

    fn flush_pending_writes(&mut self, py: Python<'_>, index: usize) -> PyResult<()> {
        let Some(conn) = self.conns[index].as_mut() else {
            return Ok(());
        };
        let io = &mut conn.io;
        if io.opos >= io.outbuf.len() {
            return Ok(());
        }
        while io.opos < io.outbuf.len() {
            let rc = unsafe {
                libc::write(
                    io.fd,
                    io.outbuf[io.opos..].as_ptr() as *const libc::c_void,
                    io.outbuf.len() - io.opos,
                )
            };
            if rc < 0 {
                let error = std::io::Error::last_os_error();
                match error.raw_os_error() {
                    Some(libc::EAGAIN) => return Ok(()),
                    Some(libc::EINTR) => continue,
                    _ => return self.drop_conn(py, index, errors::connection_lost(&error.to_string())),
                }
            }
            io.opos += rc as usize;
        }
        io.outbuf.clear();
        io.opos = 0;
        self.set_writer(py, index, false)
    }

    fn complete(&mut self, py: Python<'_>, index: usize, completion: Completion) -> PyResult<()> {
        match completion {
            Completion::Ready => {
                self.idle.push(index);
                if let Some((future, remaining)) = self.startup.take() {
                    if remaining > 1 {
                        self.startup = Some((future, remaining - 1));
                    } else {
                        self.event_loop()
                            .resolve(py, &future, py.None().into_bound(py).into_any())?;
                    }
                }
            }
            Completion::Done {
                future,
                mode,
                outcome,
            } => {
                let (generation, held) = {
                    let conn = self.conns[index].as_mut().expect("busy connection exists");
                    match mode {
                        Mode::Begin if outcome.is_ok() => conn.st.held = true,
                        Mode::Release => conn.st.held = false,
                        _ => {}
                    }
                    (conn.st.generation, conn.st.held)
                };
                if !held {
                    self.idle.push(index);
                }
                let event_loop = self.event_loop.as_ref().expect("pool used before connect()");
                match (mode, outcome) {
                    (Mode::Begin, Ok(_)) => {
                        let transaction = Py::new(
                            py,
                            Transaction {
                                pool: self.me.as_ref().expect("attached").clone_ref(py),
                                index,
                                generation,
                                finished: false,
                                poison: event_loop.poison.clone_ref(py),
                                call_soon: event_loop.call_soon.clone_ref(py),
                            },
                        )?;
                        event_loop.resolve(py, &future, transaction.into_bound(py).into_any())?;
                    }
                    (_, Ok(Done::Value(value))) => event_loop.resolve(py, &future, value.into_bound(py))?,
                    (_, Ok(Done::Nothing)) => {
                        event_loop.resolve(py, &future, py.None().into_bound(py).into_any())?
                    }
                    (_, Err(error)) => event_loop.reject(py, &future, error)?,
                }
            }
            Completion::Fatal(error) => self.drop_conn(py, index, error)?,
        }
        Ok(())
    }

    /// Sends COM_QUIT and closes an idle connection.
    fn quit(&mut self, py: Python<'_>, index: usize) -> PyResult<()> {
        if let Some(conn) = self.conns[index].as_ref()
            && matches!(conn.st.stage, Stage::Idle)
        {
            let packet = [1u8, 0, 0, 0, proto::COM_QUIT];
            unsafe {
                libc::write(conn.io.fd, packet.as_ptr() as *const libc::c_void, packet.len());
            }
        }
        self.drop_conn(py, index, errors::pool_closed())
    }

    /// Unregisters and closes a connection, failing whatever it was doing.
    fn drop_conn(&mut self, py: Python<'_>, index: usize, error: PyErr) -> PyResult<()> {
        let Some(conn) = self.conns[index].take() else {
            return Ok(());
        };
        self.by_fd.remove(&conn.io.fd);
        self.idle.retain(|&idle| idle != index);
        let event_loop = self.event_loop.as_ref().expect("pool used before connect()");
        if conn.io.reader_on {
            let _ = event_loop.remove_reader.bind(py).call1((conn.io.fd,));
        }
        if conn.io.writer_on {
            let _ = event_loop.remove_writer.bind(py).call1((conn.io.fd,));
        }
        unsafe {
            libc::close(conn.io.fd);
        }
        let during_startup = !matches!(conn.st.stage, Stage::Idle | Stage::Busy(_));
        if let Stage::Busy(active) = conn.st.stage {
            event_loop.reject(py, &active.future, error.clone_ref(py))?;
        }
        if during_startup {
            // Authentication or the handshake failed: nothing queued can
            // succeed on a connection that will fail the same way.
            if let Some((future, _)) = self.startup.take() {
                event_loop.reject(py, &future, error.clone_ref(py))?;
            }
            while let Some(job) = self.pending.pop_front() {
                event_loop.reject(py, &job.future, error.clone_ref(py))?;
            }
        }
        Ok(())
    }
}

fn build_query(py: Python<'_>, sql: &str, params: Option<&Bound<'_, PyAny>>) -> PyResult<Vec<u8>> {
    let mut payload = Vec::with_capacity(sql.len() + 64);
    payload.push(proto::COM_QUERY);
    escape::interpolate(py, &mut payload, sql, params)?;
    let mut packet = Vec::with_capacity(payload.len() + 8);
    proto::frame(&mut packet, &payload, 0);
    Ok(packet)
}

impl State {
    fn process(&mut self, py: Python<'_>, payload: &[u8], config: &Config) -> Option<Completion> {
        match self.stage {
            Stage::Connecting => Some(Completion::Fatal(errors::protocol(
                "data before connect finished",
            ))),
            Stage::AwaitHandshake => self.on_handshake(payload, config),
            Stage::AwaitAuth => self.on_auth(payload, config),
            Stage::AwaitPublicKey => self.on_public_key(payload, config),
            Stage::Init => self.on_init(payload),
            Stage::Idle => Some(Completion::Fatal(errors::protocol(
                "unexpected packet on an idle connection",
            ))),
            Stage::Busy(_) => self.on_result(py, payload),
        }
    }

    fn on_handshake(&mut self, payload: &[u8], config: &Config) -> Option<Completion> {
        if payload.first() == Some(&0xff) {
            return Some(Completion::Fatal(server_error(payload)));
        }
        let handshake = match proto::parse_handshake(payload) {
            Ok(handshake) => handshake,
            Err(_) => return Some(Completion::Fatal(errors::protocol("malformed server handshake"))),
        };
        if handshake.capabilities & proto::CLIENT_PROTOCOL_41 == 0 {
            return Some(Completion::Fatal(errors::protocol(
                "server does not speak protocol 4.1",
            )));
        }
        self.nonce = handshake.nonce;
        self.plugin = handshake.plugin;
        let auth = match proto::scramble(&self.plugin, &config.password, &self.nonce) {
            Ok(auth) => auth,
            Err(_) => {
                return Some(Completion::Fatal(errors::protocol(
                    "the server requires an unsupported authentication plugin",
                )));
            }
        };
        let mut capabilities = proto::CLIENT_LONG_PASSWORD
            | proto::CLIENT_LONG_FLAG
            | proto::CLIENT_PROTOCOL_41
            | proto::CLIENT_TRANSACTIONS
            | proto::CLIENT_SECURE_CONNECTION
            | proto::CLIENT_PLUGIN_AUTH
            | proto::CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
            | proto::CLIENT_DEPRECATE_EOF;
        if !config.database.is_empty() {
            capabilities |= proto::CLIENT_CONNECT_WITH_DB;
        }
        capabilities &= handshake.capabilities | proto::CLIENT_DEPRECATE_EOF;
        if handshake.capabilities & proto::CLIENT_DEPRECATE_EOF == 0 {
            return Some(Completion::Fatal(errors::protocol(
                "server does not support CLIENT_DEPRECATE_EOF",
            )));
        }
        let response = proto::build_handshake_response(&proto::HandshakeResponse {
            user: &config.user,
            auth: &auth,
            database: &config.database,
            plugin: &self.plugin,
            capabilities,
        });
        self.stage = Stage::AwaitAuth;
        self.queue_send(response)
    }

    /// Stages a packet to send; the pool writes it when it sees the request.
    fn queue_send(&mut self, payload: Vec<u8>) -> Option<Completion> {
        let mut packet = Vec::with_capacity(payload.len() + 4);
        self.seq = proto::frame(&mut packet, &payload, self.seq);
        self.outgoing.push(packet);
        None
    }

    fn on_auth(&mut self, payload: &[u8], config: &Config) -> Option<Completion> {
        match payload.first() {
            Some(0x00) => self.start_init(),
            Some(0xff) => Some(Completion::Fatal(server_error(payload))),
            Some(0xfe) => {
                // Authentication switch: the server names another plugin.
                let mut reader = Reader::new(&payload[1..]);
                let plugin = reader
                    .cstr()
                    .map(|name| String::from_utf8_lossy(name).into_owned());
                let data = reader.rest();
                let Ok(plugin) = plugin else {
                    return Some(Completion::Fatal(errors::protocol(
                        "malformed authentication switch",
                    )));
                };
                let nonce = data.strip_suffix(&[0]).unwrap_or(data).to_vec();
                self.plugin = plugin;
                self.nonce = nonce;
                match proto::scramble(&self.plugin, &config.password, &self.nonce) {
                    Ok(auth) => self.queue_send(auth),
                    Err(_) => Some(Completion::Fatal(errors::protocol(
                        "the server requires an unsupported authentication plugin",
                    ))),
                }
            }
            Some(0x01) => match payload.get(1) {
                Some(0x03) => None, // fast authentication succeeded; an OK follows
                Some(0x04) => {
                    // Full authentication: ask for the server's public key.
                    self.stage = Stage::AwaitPublicKey;
                    self.queue_send(vec![0x02])
                }
                _ => Some(Completion::Fatal(errors::protocol(
                    "unexpected authentication data",
                ))),
            },
            _ => Some(Completion::Fatal(errors::protocol(
                "unexpected packet during authentication",
            ))),
        }
    }

    fn on_public_key(&mut self, payload: &[u8], config: &Config) -> Option<Completion> {
        if payload.first() == Some(&0xff) {
            return Some(Completion::Fatal(server_error(payload)));
        }
        if payload.first() != Some(&0x01) {
            return Some(Completion::Fatal(errors::protocol(
                "expected the server's public key",
            )));
        }
        match proto::seal_password(&config.password, &self.nonce, &payload[1..]) {
            Ok(sealed) => {
                self.stage = Stage::AwaitAuth;
                self.queue_send(sealed)
            }
            Err(_) => Some(Completion::Fatal(errors::protocol(
                "could not encrypt the password with the server's key",
            ))),
        }
    }

    fn start_init(&mut self) -> Option<Completion> {
        match self.init_queue.pop_front() {
            Some(statement) => {
                self.stage = Stage::Init;
                self.seq = 0;
                let mut payload = Vec::with_capacity(statement.len() + 1);
                payload.push(proto::COM_QUERY);
                payload.extend_from_slice(&statement);
                self.queue_send(payload)
            }
            None => {
                self.stage = Stage::Idle;
                self.last_used = Instant::now();
                Some(Completion::Ready)
            }
        }
    }

    fn on_init(&mut self, payload: &[u8]) -> Option<Completion> {
        match payload.first() {
            Some(0x00) => self.start_init(),
            Some(0xff) => Some(Completion::Fatal(server_error(payload))),
            _ => Some(Completion::Fatal(errors::protocol(
                "init command returned a result set",
            ))),
        }
    }

    fn finish(&mut self, outcome: Result<Done, PyErr>) -> Option<Completion> {
        let stage = std::mem::replace(&mut self.stage, Stage::Idle);
        let Stage::Busy(active) = stage else {
            unreachable!("finish is only called while busy");
        };
        self.last_used = Instant::now();
        Some(Completion::Done {
            future: active.future,
            mode: active.mode,
            outcome,
        })
    }

    fn on_result(&mut self, py: Python<'_>, payload: &[u8]) -> Option<Completion> {
        let Stage::Busy(active) = &mut self.stage else {
            unreachable!();
        };
        let first = payload.first().copied().unwrap_or(0);
        match active.stage {
            ResultStage::Header => match first {
                0x00 => {
                    let ok = match proto::parse_ok(payload) {
                        Ok(ok) => ok,
                        Err(_) => return Some(Completion::Fatal(errors::protocol("malformed OK packet"))),
                    };
                    if ok.status & proto::SERVER_MORE_RESULTS_EXISTS != 0 {
                        return Some(Completion::Fatal(errors::protocol(
                            "multiple result sets are not supported",
                        )));
                    }
                    let done = match active.mode {
                        Mode::Execute => match Py::new(
                            py,
                            ExecuteResult {
                                last_row_id: ok.last_insert_id,
                                affected_rows: ok.affected_rows,
                            },
                        ) {
                            Ok(result) => Done::Value(result.into_any()),
                            Err(error) => return self.finish(Err(error)),
                        },
                        Mode::FetchAll => Done::Value(PyList::empty(py).into_any().unbind()),
                        _ => Done::Nothing,
                    };
                    self.finish(Ok(done))
                }
                0xff => {
                    let error = server_error(payload);
                    self.finish(Err(error))
                }
                0xfb => Some(Completion::Fatal(errors::protocol(
                    "LOCAL INFILE is not supported",
                ))),
                _ => {
                    let mut reader = Reader::new(payload);
                    let count = match reader.lenenc_int() {
                        Ok(count) => count as usize,
                        Err(_) => return Some(Completion::Fatal(errors::protocol("malformed column count"))),
                    };
                    active.kinds.reserve(count);
                    active.keys.reserve(count);
                    active.stage = ResultStage::Columns { expected: count };
                    None
                }
            },
            ResultStage::Columns { expected } => {
                let column = match proto::parse_column(payload) {
                    Ok(column) => column,
                    Err(_) => {
                        return Some(Completion::Fatal(errors::protocol("malformed column definition")));
                    }
                };
                let name = String::from_utf8_lossy(&column.name);
                active.keys.push(PyString::intern(py, &name).unbind());
                active.kinds.push((convert::kind_of(&column), column.flags));
                if active.keys.len() == expected {
                    active.stage = ResultStage::Rows;
                    if active.mode == Mode::FetchAll {
                        active.rows = Some(PyList::empty(py).unbind());
                    }
                }
                None
            }
            ResultStage::Rows => {
                if first == 0xfe && payload.len() < proto::MAX_PAYLOAD {
                    let ok = match proto::parse_ok(payload) {
                        Ok(ok) => ok,
                        Err(_) => {
                            return Some(Completion::Fatal(errors::protocol("malformed end of result set")));
                        }
                    };
                    if ok.status & proto::SERVER_MORE_RESULTS_EXISTS != 0 {
                        return Some(Completion::Fatal(errors::protocol(
                            "multiple result sets are not supported",
                        )));
                    }
                    let done = match active.mode {
                        Mode::FetchAll => {
                            Done::Value(active.rows.take().expect("rows list exists").into_any())
                        }
                        Mode::FetchOne | Mode::FetchVal => match active.first.take() {
                            Some(value) => Done::Value(value),
                            None => Done::Nothing,
                        },
                        Mode::Execute => match Py::new(
                            py,
                            ExecuteResult {
                                last_row_id: 0,
                                affected_rows: active.seen_rows,
                            },
                        ) {
                            Ok(result) => Done::Value(result.into_any()),
                            Err(error) => return self.finish(Err(error)),
                        },
                        _ => Done::Nothing,
                    };
                    return self.finish(Ok(done));
                }
                if first == 0xff {
                    let error = server_error(payload);
                    return self.finish(Err(error));
                }
                active.seen_rows += 1;
                match active.mode {
                    Mode::FetchAll => match build_row(py, active, payload) {
                        Ok(row) => {
                            let rows = active.rows.as_ref().expect("rows list exists").bind(py);
                            if let Err(error) = rows.append(row) {
                                return self.finish(Err(error));
                            }
                        }
                        Err(error) => return self.finish(Err(error)),
                    },
                    Mode::FetchOne if active.seen_rows == 1 => match build_row(py, active, payload) {
                        Ok(row) => active.first = Some(row.into_any().unbind()),
                        Err(error) => return self.finish(Err(error)),
                    },
                    Mode::FetchVal if active.seen_rows == 1 => {
                        let mut reader = Reader::new(payload);
                        let value = match reader.lenenc_bytes() {
                            Ok(Some(raw)) => {
                                let (kind, flags) = active.kinds[0];
                                match convert::convert(py, kind, flags, raw) {
                                    Ok(value) => value.unbind(),
                                    Err(error) => return self.finish(Err(error)),
                                }
                            }
                            Ok(None) => py.None().into_any(),
                            Err(_) => return Some(Completion::Fatal(errors::protocol("malformed row"))),
                        };
                        active.first = Some(value);
                    }
                    _ => {}
                }
                None
            }
        }
    }
}

fn build_row<'py>(py: Python<'py>, active: &Active, payload: &[u8]) -> PyResult<Bound<'py, PyDict>> {
    let row = PyDict::new(py);
    let mut reader = Reader::new(payload);
    for (key, &(kind, flags)) in active.keys.iter().zip(active.kinds.iter()) {
        let raw = reader
            .lenenc_bytes()
            .map_err(|_| errors::protocol("malformed row"))?;
        match raw {
            Some(raw) => row.set_item(key.bind(py), convert::convert(py, kind, flags, raw)?)?,
            None => row.set_item(key.bind(py), py.None())?,
        }
    }
    Ok(row)
}

fn server_error(payload: &[u8]) -> PyErr {
    match proto::parse_err(payload) {
        Ok(error) => errors::mysql_error(error.code, &error.sqlstate, &error.message),
        Err(_) => errors::protocol("malformed error packet"),
    }
}

/// A connection taken out of the pool for the duration of a transaction.
#[pyclass(unsendable, module = "beerstream1")]
pub struct Transaction {
    pool: Py<Pool>,
    index: usize,
    generation: u64,
    finished: bool,
    poison: Py<PyAny>,
    call_soon: Py<PyAny>,
}

#[pymethods]
impl Transaction {
    #[pyo3(signature = (sql, params=None))]
    fn fetch_all(&self, py: Python<'_>, sql: &str, params: Option<&Bound<'_, PyAny>>) -> PyResult<Py<PyAny>> {
        self.run(py, sql, params, Mode::FetchAll)
    }

    #[pyo3(signature = (sql, params=None))]
    fn fetch_one(&self, py: Python<'_>, sql: &str, params: Option<&Bound<'_, PyAny>>) -> PyResult<Py<PyAny>> {
        self.run(py, sql, params, Mode::FetchOne)
    }

    #[pyo3(signature = (sql, params=None))]
    fn fetch_val(&self, py: Python<'_>, sql: &str, params: Option<&Bound<'_, PyAny>>) -> PyResult<Py<PyAny>> {
        self.run(py, sql, params, Mode::FetchVal)
    }

    #[pyo3(signature = (sql, params=None))]
    fn execute(&self, py: Python<'_>, sql: &str, params: Option<&Bound<'_, PyAny>>) -> PyResult<Py<PyAny>> {
        self.run(py, sql, params, Mode::Execute)
    }

    /// Commits and returns the connection to the pool.
    fn commit(&mut self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.finished = true;
        self.run(py, "COMMIT", None, Mode::Release)
    }

    /// Rolls back and returns the connection to the pool.
    fn rollback(&mut self, py: Python<'_>) -> PyResult<Py<PyAny>> {
        self.finished = true;
        self.run(py, "ROLLBACK", None, Mode::Release)
    }

    #[getter]
    fn finished(&self) -> bool {
        self.finished
    }
}

impl Transaction {
    fn run(
        &self,
        py: Python<'_>,
        sql: &str,
        params: Option<&Bound<'_, PyAny>>,
        mode: Mode,
    ) -> PyResult<Py<PyAny>> {
        let mut pool = self.pool.bind(py).borrow_mut();
        pool.run_held(py, self.index, self.generation, sql, params, mode)
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        if self.finished {
            return;
        }
        Python::attach(|py| {
            let pool = self.pool.bind(py);
            match pool.try_borrow_mut() {
                Ok(mut pool) => {
                    let _ = pool.poison(py, self.index, self.generation);
                }
                Err(_) => {
                    let _ = self
                        .call_soon
                        .bind(py)
                        .call1((&self.poison, self.index, self.generation));
                }
            }
        });
    }
}
