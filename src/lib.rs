//! BeerStream1: a MySQL client that lives on the asyncio event loop.

mod convert;
mod errors;
mod escape;
mod pool;
mod protocol;

use pyo3::prelude::*;

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<pool::Pool>()?;
    m.add_class::<pool::Transaction>()?;
    m.add_class::<pool::ExecuteResult>()?;
    errors::register(m)?;
    Ok(())
}
