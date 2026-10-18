//! Client-side parameter interpolation for `%(name)s` placeholders, matching
//! the escaping rules of PyMySQL so queries written for it run unchanged.

use pyo3::exceptions::PyKeyError;
use pyo3::exceptions::PyTypeError;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBool;
use pyo3::types::PyBytes;
use pyo3::types::PyDate;
use pyo3::types::PyDateAccess;
use pyo3::types::PyDateTime;
use pyo3::types::PyDelta;
use pyo3::types::PyDeltaAccess;
use pyo3::types::PyDict;
use pyo3::types::PyFloat;
use pyo3::types::PyInt;
use pyo3::types::PyString;
use pyo3::types::PyTimeAccess;

/// Writes `sql` with every `%(name)s` replaced by the escaped value from
/// `params` and every `%%` collapsed to `%`. With no params the text is sent
/// verbatim, so a bare `%` only needs doubling when values are bound.
pub fn interpolate(
    py: Python<'_>,
    out: &mut Vec<u8>,
    sql: &str,
    params: Option<&Bound<'_, PyAny>>,
) -> PyResult<()> {
    let Some(params) = params else {
        out.extend_from_slice(sql.as_bytes());
        return Ok(());
    };
    let dict = params.cast::<PyDict>().ok();
    let bytes = sql.as_bytes();
    let mut start = 0;
    let mut index = 0;
    while let Some(offset) = memchr::memchr(b'%', &bytes[index..]) {
        let at = index + offset;
        out.extend_from_slice(&bytes[start..at]);
        match bytes.get(at + 1) {
            Some(b'%') => {
                out.push(b'%');
                index = at + 2;
                start = index;
            }
            Some(b'(') => {
                let close = memchr::memchr(b')', &bytes[at + 2..])
                    .ok_or_else(|| PyValueError::new_err("unterminated placeholder"))?;
                let name = &sql[at + 2..at + 2 + close];
                let after = at + 2 + close + 1;
                if bytes.get(after) != Some(&b's') {
                    return Err(PyValueError::new_err(format!(
                        "placeholder %({name}) must end with 's'"
                    )));
                }
                let value = match dict {
                    Some(dict) => dict.get_item(name)?,
                    None => params.get_item(name).ok(),
                };
                let value = value.ok_or_else(|| PyKeyError::new_err(name.to_owned()))?;
                escape_value(py, out, &value)?;
                index = after + 1;
                start = index;
            }
            _ => {
                return Err(PyValueError::new_err(
                    "a bare % in the query must be written as %% when values are bound",
                ));
            }
        }
    }
    out.extend_from_slice(&bytes[start..]);
    Ok(())
}

pub fn escape_value(py: Python<'_>, out: &mut Vec<u8>, value: &Bound<'_, PyAny>) -> PyResult<()> {
    if value.is_none() {
        out.extend_from_slice(b"NULL");
    } else if value.is_instance_of::<PyBool>() {
        out.push(if value.is_truthy()? { b'1' } else { b'0' });
    } else if let Ok(int) = value.cast::<PyInt>() {
        match int.extract::<i64>() {
            Ok(number) => out.extend_from_slice(itoa::Buffer::new().format(number).as_bytes()),
            Err(_) => out.extend_from_slice(int.str()?.to_str()?.as_bytes()),
        }
    } else if let Ok(text) = value.cast::<PyString>() {
        escape_str(out, text.to_str()?.as_bytes());
    } else if let Ok(float) = value.cast::<PyFloat>() {
        let number = float.value();
        if number.is_finite() {
            out.extend_from_slice(ryu::Buffer::new().format(number).as_bytes());
        } else {
            return Err(PyValueError::new_err("non-finite float cannot be bound"));
        }
    } else if let Ok(blob) = value.cast::<PyBytes>() {
        out.extend_from_slice(b"_binary");
        escape_str(out, blob.as_bytes());
    } else if let Ok(moment) = value.cast::<PyDateTime>() {
        out.push(b'\'');
        write_date(out, moment.get_year(), moment.get_month(), moment.get_day());
        out.push(b' ');
        write_time(
            out,
            moment.get_hour() as u32,
            moment.get_minute(),
            moment.get_second(),
            moment.get_microsecond(),
        );
        out.push(b'\'');
    } else if let Ok(day) = value.cast::<PyDate>() {
        out.push(b'\'');
        write_date(out, day.get_year(), day.get_month(), day.get_day());
        out.push(b'\'');
    } else if let Ok(delta) = value.cast::<PyDelta>() {
        let total = delta.get_days() as i64 * 86_400 + delta.get_seconds() as i64;
        let micro = delta.get_microseconds();
        let (sign, total): (&[u8], i64) = if total < 0 && micro == 0 {
            (b"-", -total)
        } else {
            (b"", total)
        };
        out.push(b'\'');
        out.extend_from_slice(sign);
        let hours = total / 3600;
        out.extend_from_slice(itoa::Buffer::new().format(hours).as_bytes());
        out.push(b':');
        write_two(out, ((total % 3600) / 60) as u32);
        out.push(b':');
        write_two(out, (total % 60) as u32);
        if micro != 0 {
            out.push(b'.');
            write_micro(out, micro as u32);
        }
        out.push(b'\'');
    } else if is_decimal(py, value)? {
        out.extend_from_slice(value.str()?.to_str()?.as_bytes());
    } else {
        return Err(PyTypeError::new_err(format!(
            "cannot bind a value of type {}",
            value.get_type().name()?
        )));
    }
    Ok(())
}

fn is_decimal(py: Python<'_>, value: &Bound<'_, PyAny>) -> PyResult<bool> {
    static DECIMAL: pyo3::sync::PyOnceLock<Py<PyAny>> = pyo3::sync::PyOnceLock::new();
    let class = DECIMAL.get_or_try_init(py, || -> PyResult<Py<PyAny>> {
        Ok(py.import("decimal")?.getattr("Decimal")?.unbind())
    })?;
    value.is_instance(class.bind(py))
}

/// Quotes a string with the same backslash escapes PyMySQL emits.
pub fn escape_str(out: &mut Vec<u8>, text: &[u8]) {
    out.reserve(text.len() + 2);
    out.push(b'\'');
    let mut start = 0;
    for (index, byte) in text.iter().enumerate() {
        let replacement: &[u8] = match byte {
            0 => b"\\0",
            b'\n' => b"\\n",
            b'\r' => b"\\r",
            b'\\' => b"\\\\",
            b'\'' => b"\\'",
            b'"' => b"\\\"",
            0x1a => b"\\Z",
            _ => continue,
        };
        out.extend_from_slice(&text[start..index]);
        out.extend_from_slice(replacement);
        start = index + 1;
    }
    out.extend_from_slice(&text[start..]);
    out.push(b'\'');
}

fn write_two(out: &mut Vec<u8>, value: u32) {
    out.push(b'0' + (value / 10) as u8);
    out.push(b'0' + (value % 10) as u8);
}

fn write_micro(out: &mut Vec<u8>, micro: u32) {
    let text = format!("{micro:06}");
    out.extend_from_slice(text.as_bytes());
}

fn write_date(out: &mut Vec<u8>, year: i32, month: u8, day: u8) {
    let text = format!("{year:04}-{month:02}-{day:02}");
    out.extend_from_slice(text.as_bytes());
}

fn write_time(out: &mut Vec<u8>, hour: u32, minute: u8, second: u8, micro: u32) {
    write_two(out, hour);
    out.push(b':');
    write_two(out, minute as u32);
    out.push(b':');
    write_two(out, second as u32);
    if micro != 0 {
        out.push(b'.');
        write_micro(out, micro);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escapes_special_characters() {
        let mut out = Vec::new();
        escape_str(&mut out, b"a'b\\c\nd");
        assert_eq!(out, b"'a\\'b\\\\c\\nd'");
    }
}
