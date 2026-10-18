//! Text-protocol column values into Python objects, with the same type
//! choices PyMySQL makes so result rows are interchangeable.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use pyo3::types::PyDate;
use pyo3::types::PyDateTime;
use pyo3::types::PyDelta;
use pyo3::types::PyFloat;
use pyo3::types::PyString;

use crate::protocol::BINARY_CHARSET;
use crate::protocol::Column;
use crate::protocol::UNSIGNED_FLAG;
use crate::protocol::types;

#[derive(Clone, Copy)]
pub enum Kind {
    Int,
    Float,
    Str,
    Bytes,
    Decimal,
    DateTime,
    Date,
    Time,
    Null,
}

pub fn kind_of(column: &Column) -> Kind {
    match column.column_type {
        types::TINY | types::SHORT | types::LONG | types::LONGLONG | types::INT24 | types::YEAR => Kind::Int,
        types::FLOAT | types::DOUBLE => Kind::Float,
        types::DECIMAL | types::NEWDECIMAL => Kind::Decimal,
        types::NULL => Kind::Null,
        types::TIMESTAMP | types::DATETIME => Kind::DateTime,
        types::DATE | types::NEWDATE => Kind::Date,
        types::TIME => Kind::Time,
        types::JSON | types::ENUM | types::SET => Kind::Str,
        types::BIT | types::GEOMETRY => Kind::Bytes,
        types::TINY_BLOB
        | types::MEDIUM_BLOB
        | types::LONG_BLOB
        | types::BLOB
        | types::VAR_STRING
        | types::STRING
        | types::VARCHAR => {
            if column.charset == BINARY_CHARSET {
                Kind::Bytes
            } else {
                Kind::Str
            }
        }
        _ => Kind::Str,
    }
}

pub fn convert<'py>(py: Python<'py>, kind: Kind, flags: u16, raw: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    Ok(match kind {
        Kind::Int => parse_int(py, raw, flags & UNSIGNED_FLAG != 0)?,
        Kind::Float => {
            let text = as_str(raw)?;
            let value: f64 = text
                .parse()
                .map_err(|_| PyValueError::new_err("malformed float from server"))?;
            PyFloat::new(py, value).into_any()
        }
        Kind::Str => PyString::new(py, as_str(raw)?).into_any(),
        Kind::Bytes => PyBytes::new(py, raw).into_any(),
        Kind::Decimal => decimal(py, as_str(raw)?)?,
        Kind::DateTime => parse_datetime(py, raw)?,
        Kind::Date => parse_date(py, raw)?,
        Kind::Time => parse_time(py, raw)?,
        Kind::Null => py.None().into_bound(py).into_any(),
    })
}

fn as_str(raw: &[u8]) -> PyResult<&str> {
    std::str::from_utf8(raw).map_err(|_| PyValueError::new_err("server sent text that is not UTF-8"))
}

fn parse_int<'py>(py: Python<'py>, raw: &[u8], unsigned: bool) -> PyResult<Bound<'py, PyAny>> {
    if raw.is_empty() {
        return Err(PyValueError::new_err("empty integer from server"));
    }
    let (negative, digits) = match raw[0] {
        b'-' => (true, &raw[1..]),
        _ => (false, raw),
    };
    if digits.len() <= 18 {
        let mut value: i64 = 0;
        for &byte in digits {
            if !byte.is_ascii_digit() {
                return Err(PyValueError::new_err("malformed integer from server"));
            }
            value = value * 10 + (byte - b'0') as i64;
        }
        if negative {
            value = -value;
        }
        return Ok(value.into_pyobject(py)?.into_any());
    }
    let text = as_str(raw)?;
    if unsigned
        && !negative
        && let Ok(value) = text.parse::<u64>()
    {
        return Ok(value.into_pyobject(py)?.into_any());
    }
    if let Ok(value) = text.parse::<i64>() {
        return Ok(value.into_pyobject(py)?.into_any());
    }
    py.get_type::<pyo3::types::PyInt>().call1((text,))
}

fn decimal<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyAny>> {
    static DECIMAL: pyo3::sync::PyOnceLock<Py<PyAny>> = pyo3::sync::PyOnceLock::new();
    let class = DECIMAL.get_or_try_init(py, || -> PyResult<Py<PyAny>> {
        Ok(py.import("decimal")?.getattr("Decimal")?.unbind())
    })?;
    class.bind(py).call1((text,))
}

fn two(raw: &[u8], at: usize) -> Option<u32> {
    let a = *raw.get(at)?;
    let b = *raw.get(at + 1)?;
    if a.is_ascii_digit() && b.is_ascii_digit() {
        Some((a - b'0') as u32 * 10 + (b - b'0') as u32)
    } else {
        None
    }
}

fn four(raw: &[u8], at: usize) -> Option<u32> {
    Some(two(raw, at)? * 100 + two(raw, at + 2)?)
}

fn fraction(raw: &[u8]) -> Option<u32> {
    // `.ffffff` with one to six digits.
    if raw.is_empty() {
        return Some(0);
    }
    if raw[0] != b'.' || raw.len() > 7 {
        return None;
    }
    let mut micro = 0u32;
    let mut scale = 100_000;
    for &byte in &raw[1..] {
        if !byte.is_ascii_digit() {
            return None;
        }
        micro += (byte - b'0') as u32 * scale;
        scale /= 10;
    }
    Some(micro)
}

fn parse_datetime<'py>(py: Python<'py>, raw: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let parsed = (|| {
        let year = four(raw, 0)?;
        let month = two(raw, 5)?;
        let day = two(raw, 8)?;
        if raw.len() < 19 {
            return Some((year, month, day, 0, 0, 0, 0));
        }
        let hour = two(raw, 11)?;
        let minute = two(raw, 14)?;
        let second = two(raw, 17)?;
        let micro = fraction(&raw[19..])?;
        Some((year, month, day, hour, minute, second, micro))
    })();
    let Some((year, month, day, hour, minute, second, micro)) = parsed else {
        return Err(PyValueError::new_err("malformed datetime from server"));
    };
    if month == 0 || day == 0 {
        // Zero dates have no datetime equivalent; PyMySQL returns None too.
        return Ok(py.None().into_bound(py).into_any());
    }
    Ok(PyDateTime::new(
        py,
        year as i32,
        month as u8,
        day as u8,
        hour as u8,
        minute as u8,
        second as u8,
        micro,
        None,
    )?
    .into_any())
}

fn parse_date<'py>(py: Python<'py>, raw: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let parsed = (|| Some((four(raw, 0)?, two(raw, 5)?, two(raw, 8)?)))();
    let Some((year, month, day)) = parsed else {
        return Err(PyValueError::new_err("malformed date from server"));
    };
    if month == 0 || day == 0 {
        return Ok(py.None().into_bound(py).into_any());
    }
    Ok(PyDate::new(py, year as i32, month as u8, day as u8)?.into_any())
}

fn parse_time<'py>(py: Python<'py>, raw: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    let (negative, body) = match raw.first() {
        Some(b'-') => (true, &raw[1..]),
        _ => (false, raw),
    };
    let parsed = (|| {
        let colon = memchr::memchr(b':', body)?;
        let hours: i64 = std::str::from_utf8(&body[..colon]).ok()?.parse().ok()?;
        let minute = two(body, colon + 1)? as i64;
        let second = two(body, colon + 4)? as i64;
        let micro = fraction(&body[colon + 6..])?;
        Some((hours * 3600 + minute * 60 + second, micro))
    })();
    let Some((seconds, micro)) = parsed else {
        return Err(PyValueError::new_err("malformed time from server"));
    };
    let (seconds, micro) = if negative {
        (-seconds, -(micro as i32))
    } else {
        (seconds, micro as i32)
    };
    Ok(PyDelta::new(py, 0, seconds as i32, micro, true)?.into_any())
}
