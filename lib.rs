#![crate_name="otp"]
#![crate_type="lib"]

extern crate openssl;
extern crate base32;
extern crate time;
extern crate byteorder;

use time::get_time;
use openssl::crypto::hash::Type as HashType;
use openssl::crypto::hmac::hmac;
use byteorder::{ByteOrder, BigEndian};


/// Decodes a secret (given as an RFC4648 base32-encoded ASCII string)
/// into a byte string
fn decode_secret(secret: &str) -> Option<Vec<u8>> {
    base32::decode(base32::Alphabet::RFC4648 { padding: false }, secret)
}

/// Calculates the HMAC digest for the given secret and counter.
fn calc_digest(decoded_secret: &[u8], counter: u64) -> Vec<u8> {    
    let mut bytes = [0; 8];
    BigEndian::write_u64(&mut bytes, counter);
    hmac(HashType::SHA1, decoded_secret, &bytes)    
}

/// Encodes the HMAC digest into a 6-digit integer.
fn encode_digest(digest: &[u8]) -> u32 {
    let offset = *digest.last().unwrap() as usize & 0xf;
    let code: u32 = BigEndian::read_u32(&digest[offset..offset+4]);

    (code & 0x7fffffff) % 1_000_000
}

/// Performs the [HMAC-based One-time Password Algorithm](http://en.wikipedia.org/wiki/HMAC-based_One-time_Password_Algorithm)
/// (HOTP) given an RFC4648 base32 encoded secret, and an integer counter.
pub fn make_hotp(secret: &str, counter: u64) -> Option<u32> {
    decode_secret(secret).map(|decoded| {
        encode_digest(&calc_digest(&decoded, counter))
    })
}

/// Helper function for `make_totp` to make it testable. Note that times
/// before Unix epoch are not supported.
fn make_totp_helper(secret: &str, time_step: u64, skew: i64, time: u64) -> Option<u32> {
    let counter = ((time as i64 + skew) as u64) / time_step;
    make_hotp(secret, counter)
}

/// Performs the [Time-based One-time Password Algorithm](http://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm)
/// (TOTP) given an RFC4648 base32 encoded secret, the time step in seconds,
/// and a skew in seconds.
pub fn make_totp(secret: &str, time_step: u64, skew: i64) -> Option<u32> {
    let now = get_time();
    make_totp_helper(secret, time_step, skew, now.sec as u64)
}

#[cfg(test)]
mod tests {
    use super::{make_hotp, make_totp_helper};

    #[test]
    fn hotp() {
        assert_eq!(make_hotp("base32secret3232", 0), Some(260182));
        assert_eq!(make_hotp("base32secret3232", 1), Some(55283));
        assert_eq!(make_hotp("base32secret3232", 1401), Some(316439));
    }

    #[test]
    fn totp() {
        assert_eq!(make_totp_helper("base32secret3232", 30, 0, 0), Some(260182));
        assert_eq!(make_totp_helper("base32secret3232", 3600, 0, 7), Some(260182));
        assert_eq!(make_totp_helper("base32secret3232", 30, 0, 35), Some(55283));
        assert_eq!(make_totp_helper("base32secret3232", 1, -2, 1403), Some(316439));
    }
}
