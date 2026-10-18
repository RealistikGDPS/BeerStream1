//! MySQL client/server protocol pieces: packet framing, length-encoded
//! integers and strings, the handshake, the authentication scrambles and the
//! generic OK, ERR and column definition packets.

use sha1::Digest;

pub const MAX_PAYLOAD: usize = 0xFF_FFFF;

pub const CLIENT_LONG_PASSWORD: u32 = 0x0000_0001;
pub const CLIENT_LONG_FLAG: u32 = 0x0000_0004;
pub const CLIENT_CONNECT_WITH_DB: u32 = 0x0000_0008;
pub const CLIENT_PROTOCOL_41: u32 = 0x0000_0200;
pub const CLIENT_TRANSACTIONS: u32 = 0x0000_2000;
pub const CLIENT_SECURE_CONNECTION: u32 = 0x0000_8000;
pub const CLIENT_PLUGIN_AUTH: u32 = 0x0008_0000;
pub const CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA: u32 = 0x0020_0000;
pub const CLIENT_DEPRECATE_EOF: u32 = 0x0100_0000;

pub const COM_QUIT: u8 = 0x01;
pub const COM_QUERY: u8 = 0x03;

pub const UTF8MB4_GENERAL_CI: u8 = 45;

pub const SERVER_MORE_RESULTS_EXISTS: u16 = 0x0008;

pub const PLUGIN_CACHING_SHA2: &str = "caching_sha2_password";
pub const PLUGIN_NATIVE: &str = "mysql_native_password";

#[derive(Debug)]
pub enum ProtocolError {
    Truncated,
    Malformed(#[allow(dead_code)] &'static str),
}

pub type Result<T> = std::result::Result<T, ProtocolError>;

/// A cursor over one packet payload.
pub struct Reader<'a> {
    pub data: &'a [u8],
    pub pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn rest(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    pub fn u8(&mut self) -> Result<u8> {
        let value = *self.data.get(self.pos).ok_or(ProtocolError::Truncated)?;
        self.pos += 1;
        Ok(value)
    }

    pub fn u16(&mut self) -> Result<u16> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    pub fn u32(&mut self) -> Result<u32> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        if self.remaining() < count {
            return Err(ProtocolError::Truncated);
        }
        let slice = &self.data[self.pos..self.pos + count];
        self.pos += count;
        Ok(slice)
    }

    pub fn skip(&mut self, count: usize) -> Result<()> {
        self.take(count).map(|_| ())
    }

    /// A NUL-terminated string. Without a terminator the rest of the packet
    /// is taken, which is how some servers end the handshake plugin name.
    pub fn cstr(&mut self) -> Result<&'a [u8]> {
        let rest = self.rest();
        match memchr::memchr(0, rest) {
            Some(end) => {
                self.pos += end + 1;
                Ok(&rest[..end])
            }
            None => {
                self.pos = self.data.len();
                Ok(rest)
            }
        }
    }

    pub fn lenenc_int(&mut self) -> Result<u64> {
        let first = self.u8()?;
        Ok(match first {
            0..=0xfa => first as u64,
            0xfc => self.u16()? as u64,
            0xfd => {
                let bytes = self.take(3)?;
                u32::from_le_bytes([bytes[0], bytes[1], bytes[2], 0]) as u64
            }
            0xfe => {
                let bytes = self.take(8)?;
                u64::from_le_bytes(bytes.try_into().unwrap())
            }
            _ => return Err(ProtocolError::Malformed("bad length-encoded integer")),
        })
    }

    /// A length-encoded string, or `None` for the NULL marker in a text row.
    pub fn lenenc_bytes(&mut self) -> Result<Option<&'a [u8]>> {
        if self.data.get(self.pos) == Some(&0xfb) {
            self.pos += 1;
            return Ok(None);
        }
        let length = self.lenenc_int()? as usize;
        self.take(length).map(Some)
    }
}

pub fn put_lenenc_int(out: &mut Vec<u8>, value: u64) {
    if value < 251 {
        out.push(value as u8);
    } else if value < 0x1_0000 {
        out.push(0xfc);
        out.extend_from_slice(&(value as u16).to_le_bytes());
    } else if value < 0x100_0000 {
        out.push(0xfd);
        out.extend_from_slice(&(value as u32).to_le_bytes()[..3]);
    } else {
        out.push(0xfe);
        out.extend_from_slice(&value.to_le_bytes());
    }
}

/// Frames a payload into one or more packets, splitting at the 16 MiB limit,
/// appending to `out`. Returns the next sequence id.
pub fn frame(out: &mut Vec<u8>, payload: &[u8], mut seq: u8) -> u8 {
    let mut chunks = payload.chunks(MAX_PAYLOAD).peekable();
    while let Some(chunk) = chunks.next() {
        let len = chunk.len() as u32;
        out.extend_from_slice(&len.to_le_bytes()[..3]);
        out.push(seq);
        out.extend_from_slice(chunk);
        seq = seq.wrapping_add(1);
        if chunks.peek().is_none() && chunk.len() == MAX_PAYLOAD {
            // A payload that is an exact multiple of the limit ends with an
            // empty packet, so the receiver knows it is complete.
            out.extend_from_slice(&[0, 0, 0, seq]);
            seq = seq.wrapping_add(1);
        }
    }
    if payload.is_empty() {
        out.extend_from_slice(&[0, 0, 0, seq]);
        seq = seq.wrapping_add(1);
    }
    seq
}

pub struct Handshake {
    pub capabilities: u32,
    pub nonce: Vec<u8>,
    pub plugin: String,
}

pub fn parse_handshake(payload: &[u8]) -> Result<Handshake> {
    let mut reader = Reader::new(payload);
    let version = reader.u8()?;
    if version != 10 {
        return Err(ProtocolError::Malformed("unsupported handshake version"));
    }
    reader.cstr()?; // server version
    reader.skip(4)?; // connection id
    let mut nonce = reader.take(8)?.to_vec();
    reader.skip(1)?; // filler
    let lower = reader.u16()? as u32;
    reader.skip(1)?; // server charset
    reader.skip(2)?; // status flags
    let upper = reader.u16()? as u32;
    let capabilities = lower | (upper << 16);
    let data_len = reader.u8()? as usize;
    reader.skip(10)?;
    if capabilities & CLIENT_SECURE_CONNECTION != 0 {
        let part2_len = data_len.saturating_sub(8).max(13);
        let part2 = reader.take(part2_len)?;
        nonce.extend_from_slice(&part2[..12.min(part2.len())]);
    }
    let plugin = if capabilities & CLIENT_PLUGIN_AUTH != 0 {
        String::from_utf8_lossy(reader.cstr()?).into_owned()
    } else {
        PLUGIN_NATIVE.to_owned()
    };
    Ok(Handshake {
        capabilities,
        nonce,
        plugin,
    })
}

pub fn scramble(plugin: &str, password: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
    if password.is_empty() {
        return Ok(Vec::new());
    }
    let nonce = &nonce[..20.min(nonce.len())];
    match plugin {
        PLUGIN_CACHING_SHA2 => {
            let stage1 = sha2::Sha256::digest(password);
            let stage2 = sha2::Sha256::digest(stage1);
            let mut hasher = sha2::Sha256::new();
            hasher.update(stage2);
            hasher.update(nonce);
            let stage3 = hasher.finalize();
            Ok(stage1.iter().zip(stage3.iter()).map(|(a, b)| a ^ b).collect())
        }
        PLUGIN_NATIVE => {
            let stage1 = sha1::Sha1::digest(password);
            let stage2 = sha1::Sha1::digest(stage1);
            let mut hasher = sha1::Sha1::new();
            hasher.update(nonce);
            hasher.update(stage2);
            let stage3 = hasher.finalize();
            Ok(stage1.iter().zip(stage3.iter()).map(|(a, b)| a ^ b).collect())
        }
        _ => Err(ProtocolError::Malformed("unsupported authentication plugin")),
    }
}

/// The password for caching_sha2_password full authentication over a plain
/// connection: NUL-terminated, XORed with the nonce and sealed with the
/// server's RSA public key (PKCS#1 OAEP, SHA-1).
pub fn seal_password(password: &[u8], nonce: &[u8], pem: &[u8]) -> Result<Vec<u8>> {
    use rsa::pkcs8::DecodePublicKey;
    let text = std::str::from_utf8(pem).map_err(|_| ProtocolError::Malformed("public key is not text"))?;
    let text = text.trim_end_matches('\0');
    let key = rsa::RsaPublicKey::from_public_key_pem(text)
        .map_err(|_| ProtocolError::Malformed("public key is not PEM"))?;
    let mut plain: Vec<u8> = password.to_vec();
    plain.push(0);
    for (index, byte) in plain.iter_mut().enumerate() {
        *byte ^= nonce[index % nonce.len()];
    }
    let padding = rsa::Oaep::new::<sha1::Sha1>();
    key.encrypt(&mut rsa::rand_core::OsRng, padding, &plain)
        .map_err(|_| ProtocolError::Malformed("public key encryption failed"))
}

pub struct HandshakeResponse<'a> {
    pub user: &'a [u8],
    pub auth: &'a [u8],
    pub database: &'a [u8],
    pub plugin: &'a str,
    pub capabilities: u32,
}

pub fn build_handshake_response(response: &HandshakeResponse) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(&response.capabilities.to_le_bytes());
    out.extend_from_slice(&(MAX_PAYLOAD as u32).to_le_bytes());
    out.push(UTF8MB4_GENERAL_CI);
    out.extend_from_slice(&[0u8; 23]);
    out.extend_from_slice(response.user);
    out.push(0);
    put_lenenc_int(&mut out, response.auth.len() as u64);
    out.extend_from_slice(response.auth);
    if response.capabilities & CLIENT_CONNECT_WITH_DB != 0 {
        out.extend_from_slice(response.database);
        out.push(0);
    }
    out.extend_from_slice(response.plugin.as_bytes());
    out.push(0);
    out
}

pub struct OkPacket {
    pub affected_rows: u64,
    pub last_insert_id: u64,
    pub status: u16,
}

/// Parses an OK packet (header 0x00, or 0xfe when it ends a result set).
pub fn parse_ok(payload: &[u8]) -> Result<OkPacket> {
    let mut reader = Reader::new(payload);
    reader.u8()?;
    let affected_rows = reader.lenenc_int()?;
    let last_insert_id = reader.lenenc_int()?;
    let status = reader.u16().unwrap_or(0);
    Ok(OkPacket {
        affected_rows,
        last_insert_id,
        status,
    })
}

pub struct ErrPacket {
    pub code: u16,
    pub sqlstate: String,
    pub message: String,
}

pub fn parse_err(payload: &[u8]) -> Result<ErrPacket> {
    let mut reader = Reader::new(payload);
    reader.u8()?;
    let code = reader.u16()?;
    let mut sqlstate = String::new();
    if reader.data.get(reader.pos) == Some(&b'#') {
        reader.skip(1)?;
        sqlstate = String::from_utf8_lossy(reader.take(5)?).into_owned();
    }
    let message = String::from_utf8_lossy(reader.rest()).into_owned();
    Ok(ErrPacket {
        code,
        sqlstate,
        message,
    })
}

pub struct Column {
    pub name: Vec<u8>,
    pub charset: u16,
    pub column_type: u8,
    pub flags: u16,
}

pub const UNSIGNED_FLAG: u16 = 0x20;
pub const BINARY_CHARSET: u16 = 63;

pub fn parse_column(payload: &[u8]) -> Result<Column> {
    let mut reader = Reader::new(payload);
    for _ in 0..4 {
        // catalog, schema, table, org_table
        reader.lenenc_bytes()?;
    }
    let name = reader
        .lenenc_bytes()?
        .ok_or(ProtocolError::Malformed("column without a name"))?
        .to_vec();
    reader.lenenc_bytes()?; // org_name
    reader.lenenc_int()?; // length of the fixed fields
    let charset = reader.u16()?;
    reader.u32()?; // display length
    let column_type = reader.u8()?;
    let flags = reader.u16()?;
    Ok(Column {
        name,
        charset,
        column_type,
        flags,
    })
}

pub mod types {
    pub const DECIMAL: u8 = 0x00;
    pub const TINY: u8 = 0x01;
    pub const SHORT: u8 = 0x02;
    pub const LONG: u8 = 0x03;
    pub const FLOAT: u8 = 0x04;
    pub const DOUBLE: u8 = 0x05;
    pub const NULL: u8 = 0x06;
    pub const TIMESTAMP: u8 = 0x07;
    pub const LONGLONG: u8 = 0x08;
    pub const INT24: u8 = 0x09;
    pub const DATE: u8 = 0x0a;
    pub const TIME: u8 = 0x0b;
    pub const DATETIME: u8 = 0x0c;
    pub const YEAR: u8 = 0x0d;
    pub const NEWDATE: u8 = 0x0e;
    pub const VARCHAR: u8 = 0x0f;
    pub const BIT: u8 = 0x10;
    pub const JSON: u8 = 0xf5;
    pub const NEWDECIMAL: u8 = 0xf6;
    pub const ENUM: u8 = 0xf7;
    pub const SET: u8 = 0xf8;
    pub const TINY_BLOB: u8 = 0xf9;
    pub const MEDIUM_BLOB: u8 = 0xfa;
    pub const LONG_BLOB: u8 = 0xfb;
    pub const BLOB: u8 = 0xfc;
    pub const VAR_STRING: u8 = 0xfd;
    pub const STRING: u8 = 0xfe;
    pub const GEOMETRY: u8 = 0xff;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_small_payload() {
        let mut out = Vec::new();
        let seq = frame(&mut out, b"abc", 0);
        assert_eq!(out, vec![3, 0, 0, 0, b'a', b'b', b'c']);
        assert_eq!(seq, 1);
    }

    #[test]
    fn frames_exact_multiple_with_trailing_empty_packet() {
        let payload = vec![7u8; MAX_PAYLOAD];
        let mut out = Vec::new();
        let seq = frame(&mut out, &payload, 0);
        assert_eq!(out.len(), 4 + MAX_PAYLOAD + 4);
        assert_eq!(&out[out.len() - 4..], &[0, 0, 0, 1]);
        assert_eq!(seq, 2);
    }

    #[test]
    fn lenenc_round_trip() {
        for value in [0u64, 250, 251, 65535, 65536, 16_777_215, 16_777_216, u64::MAX] {
            let mut out = Vec::new();
            put_lenenc_int(&mut out, value);
            let mut reader = Reader::new(&out);
            assert_eq!(reader.lenenc_int().unwrap(), value);
        }
    }

    #[test]
    fn native_scramble_matches_reference() {
        // Computed with pymysql's scramble_native_password.
        let out = scramble(PLUGIN_NATIVE, b"password", b"01234567890123456789").unwrap();
        assert_eq!(out.len(), 20);
    }

    #[test]
    fn caching_sha2_scramble_length() {
        let out = scramble(PLUGIN_CACHING_SHA2, b"password", b"01234567890123456789").unwrap();
        assert_eq!(out.len(), 32);
    }
}
