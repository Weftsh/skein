//! ULIDs (lowercase Crockford base32): time-sortable, URL-safe, and safe as
//! object-store key components (alphanumeric only). No external deps —
//! randomness comes from the OS.

use std::fs::File;
use std::io::Read;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

static URANDOM: Mutex<Option<File>> = Mutex::new(None);

fn random_bytes(buf: &mut [u8]) {
    let mut guard = URANDOM.lock().unwrap();
    if guard.is_none() {
        *guard = Some(File::open("/dev/urandom").expect("open /dev/urandom"));
    }
    guard
        .as_mut()
        .unwrap()
        .read_exact(buf)
        .expect("read /dev/urandom");
}

/// Is this the shape of an id we mint? 26 chars of lowercase Crockford
/// base32.
///
/// Used to short-circuit lookups before hostile bytes (NUL, control
/// characters, injection shapes) reach a query — where a NUL surfaces as
/// a database error rather than the "not found" the lookup contract
/// promises. An id that cannot exist names nothing.
pub fn valid_id(s: &str) -> bool {
    s.len() == 26 && s.bytes().all(|b| ALPHABET.contains(&b))
}

/// `n` bytes from the OS CSPRNG. The same source the ULIDs and token
/// secrets use, exposed so password salting does not need to pull in a
/// second randomness stack.
pub fn random(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    random_bytes(&mut buf);
    buf
}

/// 26-char ULID: 48-bit millisecond timestamp + 80 random bits.
pub fn ulid() -> String {
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
        & 0xFFFF_FFFF_FFFF;
    let mut bytes = [0u8; 16];
    bytes[..6].copy_from_slice(&ms.to_be_bytes()[2..8]);
    random_bytes(&mut bytes[6..]);
    encode_base32(&bytes)
}

/// Crockford base32 of 16 bytes -> 26 chars (2 leading bits zero).
fn encode_base32(bytes: &[u8; 16]) -> String {
    let mut hi = u64::from_be_bytes(bytes[..8].try_into().unwrap()) as u128;
    hi = (hi << 64) | u64::from_be_bytes(bytes[8..].try_into().unwrap()) as u128;
    let mut out = [0u8; 26];
    for i in (0..26).rev() {
        out[i] = ALPHABET[(hi & 0x1f) as usize];
        hi >>= 5;
    }
    String::from_utf8(out.to_vec()).unwrap()
}

/// Random token secret: 32 bytes, base32 (52 chars).
pub fn token_secret() -> String {
    let mut bytes = [0u8; 32];
    random_bytes(&mut bytes);
    let mut out = String::with_capacity(52);
    let mut acc: u64 = 0;
    let mut nbits = 0;
    for b in bytes {
        acc = (acc << 8) | b as u64;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(ALPHABET[((acc >> nbits) & 0x1f) as usize] as char);
        }
    }
    if nbits > 0 {
        out.push(ALPHABET[((acc << (5 - nbits)) & 0x1f) as usize] as char);
    }
    out
}

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ulids_are_unique_sortable_and_urlsafe() {
        let a = ulid();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = ulid();
        assert_ne!(a, b);
        assert!(a < b, "{a} !< {b}");
        assert_eq!(a.len(), 26);
        assert!(a.bytes().all(|c| c.is_ascii_alphanumeric()));
    }

    #[test]
    fn secrets_are_long_and_distinct() {
        let s = token_secret();
        assert!(s.len() >= 52);
        assert_ne!(s, token_secret());
    }
}
