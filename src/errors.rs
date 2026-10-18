//! The exception hierarchy. Server errors carry the MySQL error code and
//! SQLSTATE as attributes next to the message.

use pyo3::prelude::*;

pyo3::create_exception!(
    beerstream1,
    Error,
    pyo3::exceptions::PyException,
    "Base of every BeerStream1 error."
);
pyo3::create_exception!(
    beerstream1,
    MySQLError,
    Error,
    "An error reported by the server; has `code` and `sqlstate`."
);
pyo3::create_exception!(
    beerstream1,
    ProtocolError,
    Error,
    "The server sent something the client does not understand."
);
pyo3::create_exception!(
    beerstream1,
    ConnectionLost,
    Error,
    "The connection dropped before the request finished."
);
pyo3::create_exception!(beerstream1, PoolClosed, Error, "The pool was closed.");

pub fn mysql_error(code: u16, sqlstate: &str, message: &str) -> PyErr {
    let error = MySQLError::new_err(format!("({code}, '{message}')"));
    Python::attach(|py| {
        let value = error.value(py);
        let _ = value.setattr("code", code);
        let _ = value.setattr("sqlstate", sqlstate);
        let _ = value.setattr("message", message);
    });
    error
}

pub fn protocol(message: &str) -> PyErr {
    ProtocolError::new_err(message.to_owned())
}

pub fn connection_lost(message: &str) -> PyErr {
    ConnectionLost::new_err(message.to_owned())
}

pub fn pool_closed() -> PyErr {
    PoolClosed::new_err("the pool is closed")
}

pub fn register(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let py = m.py();
    m.add("Error", py.get_type::<Error>())?;
    m.add("MySQLError", py.get_type::<MySQLError>())?;
    m.add("ProtocolError", py.get_type::<ProtocolError>())?;
    m.add("ConnectionLost", py.get_type::<ConnectionLost>())?;
    m.add("PoolClosed", py.get_type::<PoolClosed>())?;
    Ok(())
}
