//! A library for interoperability with Ruby's `Rack::Session::Cookie` http
//! cookie encoding.
//!
//! This library provides serde compatible encoding and decoding, plus message
//! authentication of client side session cookies.
//!
//! # Examples
//!
//! Encoding:
//!
//! ```
//! use serde::{Deserialize, Serialize};
//! 
//! use rack_session::{Base64, Cookie, Json};
//! 
//! #[derive(Debug, Deserialize, PartialEq, Serialize)]
//! struct Session {
//!     session_id: String,
//!     user_id: Option<u64>,
//!     is_signed_in: bool,
//! }
//! 
//! let cookie = Cookie::<Base64<Json>>::new("super secret");
//! 
//! let session = Session {
//!     session_id: String::from("ac762bf56f7360fc45701ff8373ed519c103762bf57bec09d5280659f59cb038"),
//!     user_id: Some(42),
//!     is_signed_in: true,
//! };
//! 
//! assert_eq!(
//!     cookie.to_string(&session).unwrap(),
//!     "eyJzZXNzaW9uX2lkIjoiYWM3NjJiZjU2ZjczNjBmYzQ1NzAxZmY4MzczZWQ1MTljMTAzNzYyYmY1N2JlYzA5ZDUyODA2NTlmNTljYjAzOCIsInVzZXJfaWQiOjQyLCJpc19zaWduZWRfaW4iOnRydWV9--a49a66f88f64651f2c5846c90ff42dd8d31fe96c"
//! );
//! ```
//!
//! Decoding:
//!
//! ```
//! use serde::{Deserialize, Serialize};
//! 
//! use rack_session::{Base64, Cookie, Json};
//! 
//! #[derive(Debug, Deserialize, PartialEq, Serialize)]
//! struct Session {
//!     session_id: String,
//!     user_id: Option<u64>,
//!     is_signed_in: bool,
//! }
//! 
//! let cookie = Cookie::<Base64<Json>>::new("super secret");
//! 
//! assert_eq!(
//!     cookie.from_str::<Session>("eyJzZXNzaW9uX2lkIjoiYWM3NjJiZjU2ZjczNjBmYzQ1NzAxZmY4MzczZWQ1MTljMTAzNzYyYmY1N2JlYzA5ZDUyODA2NTlmNTljYjAzOCIsInVzZXJfaWQiOjQyLCJpc19zaWduZWRfaW4iOnRydWV9--a49a66f88f64651f2c5846c90ff42dd8d31fe96c").unwrap(),
//!     Session {
//!         session_id: String::from("ac762bf56f7360fc45701ff8373ed519c103762bf57bec09d5280659f59cb038"),
//!         user_id: Some(42),
//!         is_signed_in: true,
//!     }
//! );
//! ```

mod coder;

use std::{error::Error as StdError, marker::PhantomData};

use hmac::{Hmac, Mac, NewMac};
use percent_encoding::{percent_decode, utf8_percent_encode, AsciiSet};
use serde::{de::DeserializeOwned, Serialize};
use sha1::Sha1;

pub use coder::{Base64, Json, Zip};
use coder::Coder;

/// A structure for encoding, decoding, and message authentication of cookies.
pub struct Cookie<C> {
    read_write_key: Vec<u8>,
    read_keys: Vec<Vec<u8>>,
    phantom: PhantomData<C>,
}

impl<C> Cookie<C> {
    /// Construct a new `Cookie` with the given `read_write_key` for message
    /// authentication when encoding and decoding cookies.
    ///
    /// `read_write_key` is effectivly the `secret` argument from Ruby's
    /// `Rack::Session::Cookie`.
    pub fn new<I: Into<Vec<u8>>>(read_write_key: I) -> Self {
        Self {
            read_write_key: read_write_key.into(),
            read_keys: Vec::new(),
            phantom: PhantomData,
        }
    }

    /// Add `read_key` as a second (third, etc) key to try for authentication
    /// when decoding cookies.
    ///
    /// This is effectivly the `old_secret` argument from Ruby's
    /// `Rack::Session::Cookie`.
    pub fn add_read_key<I: Into<Vec<u8>>>(&mut self, read_key: I) {
        self.read_keys.push(read_key.into());
    }
}

/// An error that can be returned when decoding a cookie.
#[derive(Debug)]
pub enum DecodeError {
    Utf8,
    MissingHmac,
    BadHmac,
    MissingData,
    Hmac,
    Coder(Box<dyn StdError>),
}

impl From<std::str::Utf8Error> for DecodeError {
    fn from(_: std::str::Utf8Error) -> Self {
        DecodeError::Utf8
    }
}

impl From<hex::FromHexError> for DecodeError {
    fn from(_: hex::FromHexError) -> Self {
        DecodeError::BadHmac
    }
}

impl From<hmac::crypto_mac::MacError> for DecodeError {
    fn from(_: hmac::crypto_mac::MacError) -> Self {
        DecodeError::Hmac
    }
}

impl From<coder::Base64Error> for DecodeError {
    fn from(error: coder::Base64Error) -> Self {
        DecodeError::Coder(Box::new(error))
    }
}

impl From<coder::ZipError> for DecodeError {
    fn from(error: coder::ZipError) -> Self {
        DecodeError::Coder(Box::new(error))
    }
}

/// An error that can be returned when encoding a cookie.
#[derive(Debug)]
pub enum EncodeError {
    Coder(Box<dyn StdError>),
}

impl From<coder::Base64Error> for EncodeError {
    fn from(error: coder::Base64Error) -> Self {
        EncodeError::Coder(Box::new(error))
    }
}

impl From<coder::ZipError> for EncodeError {
    fn from(error: coder::ZipError) -> Self {
        EncodeError::Coder(Box::new(error))
    }
}

const WWWCOMP_ENCODE_SET: &AsciiSet = &percent_encoding::CONTROLS.add(b' ').add(b'!').add(b'"').add(b'#').add(b'$').add(b'%').add(b'&').add(b'\'').add(b'(').add(b')').add(b'+').add(b',').add(b'/').add(b':').add(b';').add(b'<').add(b'=').add(b'>').add(b'?').add(b'@').add(b'[').add(b'\\').add(b']').add(b'^').add(b'`').add(b'{').add(b'|').add(b'}').add(b'~'); // "

impl<C> Cookie<C>
where
    C: Coder,
    DecodeError: From<C::DecodeError>,
    EncodeError: From<C::EncodeError>,
{
    /// Decode a session of type `T` from the given string.
    ///
    /// # Errors
    ///
    /// Returns an error if the string is badly formatted, the message
    /// authentication fails, or the coder can not decode the session.
    pub fn from_str<T>(&self, s: &str) -> Result<T, DecodeError>
    where
        T: DeserializeOwned,
    {
        let percent_decoded = percent_decode(s.as_bytes()).decode_utf8()?;
        let mut parts = percent_decoded.rsplitn(2, "--");
        let hmac = match parts.next() {
            Some(p) => hex::decode(p)?,
            None => return Err(DecodeError::MissingHmac),
        };
        let data = match parts.next() {
            Some(p) => p,
            None => return Err(DecodeError::MissingData),
        };

        let mut error = None;
        for key in std::iter::once(&self.read_write_key).chain(self.read_keys.iter()) {
            let mut mac = Hmac::<Sha1>::new_varkey(&key).unwrap();
            mac.update(data.as_bytes());
            match mac.verify(&hmac) {
                Ok(()) => return Ok(C::from_str(&data)?),
                Err(e) => {
                    error.get_or_insert(e);
                }
            }
        }
        Err(error.unwrap().into())
    }

    /// Encode a session to a String.
    ///
    /// # Errors
    ///
    /// If the coder can not encode the session then an error is returned.
    pub fn to_string<T>(&self, value: &T) -> Result<String, EncodeError>
    where
        T: Serialize,
    {
        let data = C::to_string(value)?;

        let mut mac = Hmac::<Sha1>::new_varkey(&self.read_write_key).unwrap();
        mac.update(data.as_bytes());
        let hmac = hex::encode(mac.finalize().into_bytes());

        Ok(format!("{}--{}", utf8_percent_encode(&data, WWWCOMP_ENCODE_SET), hmac))
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::{Base64, Cookie, Json, Zip};

    #[derive(Debug, Deserialize, PartialEq, Serialize)]
    struct Session {
        session_id: String,
        foo: String,
        baz: i64,
        qux: Vec<String>,
    }

    #[test]
    fn from_str() {
        let cookie = Cookie::<Base64<Json>>::new("super secret");

        let session = cookie.from_str::<Session>("eyJzZXNzaW9uX2lkIjoiYWM3NjJiZjU2ZjczNjBmYzQ1NzAxZmY4MzczZWQ1MTljMTAzNzYyYmY1N2JlYzA5ZDUyODA2NTlmNTljYjAzOCIsImZvbyI6ImJhciIsImJheiI6MTIzLCJxdXgiOlsiYSIsImIiLCJjIl19--d488db9c924687bee43406dd7c1c9bd24d356d5a").unwrap();

        assert_eq!(
            session,
            Session {
                session_id: "ac762bf56f7360fc45701ff8373ed519c103762bf57bec09d5280659f59cb038"
                    .into(),
                foo: "bar".into(),
                baz: 123,
                qux: vec!["a".into(), "b".into(), "c".into()],
            }
        );
    }

    // Rack < 2.1.0 uses base64 encoding that includes newlines
    #[test]
    fn from_rack_lt_2_1_str() {
        let cookie = Cookie::<Base64<Json>>::new("super secret");

        let session = cookie.from_str::<Session>("eyJzZXNzaW9uX2lkIjoiYWM3NjJiZjU2ZjczNjBmYzQ1NzAxZmY4MzczZWQ1%0AMTljMTAzNzYyYmY1N2JlYzA5ZDUyODA2NTlmNTljYjAzOCIsImZvbyI6ImJh%0AciIsImJheiI6MTIzLCJxdXgiOlsiYSIsImIiLCJjIl19%0A--2351e1492ebc3107efe5e8070b07b473ab0ce680").unwrap();

        assert_eq!(
            session,
            Session {
                session_id: "ac762bf56f7360fc45701ff8373ed519c103762bf57bec09d5280659f59cb038"
                    .into(),
                foo: "bar".into(),
                baz: 123,
                qux: vec!["a".into(), "b".into(), "c".into()],
            }
        );
    }

    #[test]
    fn from_zip_str() {
        let cookie = Cookie::<Base64<Zip<Json>>>::new("super secret");

        let session = cookie.from_str::<Session>("eJwVjEsKAjEQBe%2FS61mkJ0nncxUReekkMBuDBkEcvLtxUVCLok6abc5j3G9HpUwSwUZcjZygvqXqYGwwbLl6hKRNYoSVEDo6e4iq6%2BoFxUVxuwVt1MdYo4Ln8oIPZd7tRo%2FXm%2FKF%2FkFZKF2%2FP5LhIi8%3D--b6c48a0ed3836d9d3653cbde7f7332da0f312518").unwrap();

        assert_eq!(
            session,
            Session {
                session_id: "68a1064d819ac5e9d4a0370131d5a79ce688a3677faf15a6cc4fc56ab486423a"
                    .into(),
                foo: "bar".into(),
                baz: 123,
                qux: vec!["a".into(), "b".into(), "c".into()],
            }
        );
    }

    #[test]
    fn to_string() {
        let cookie = Cookie::<Base64<Json>>::new("super secret");

        let session = Session {
            session_id: "ac762bf56f7360fc45701ff8373ed519c103762bf57bec09d5280659f59cb038".into(),
            foo: "bar".into(),
            baz: 123,
            qux: vec!["a".into(), "b".into(), "c".into()],
        };

        assert_eq!(cookie.to_string(&session).unwrap(), "eyJzZXNzaW9uX2lkIjoiYWM3NjJiZjU2ZjczNjBmYzQ1NzAxZmY4MzczZWQ1MTljMTAzNzYyYmY1N2JlYzA5ZDUyODA2NTlmNTljYjAzOCIsImZvbyI6ImJhciIsImJheiI6MTIzLCJxdXgiOlsiYSIsImIiLCJjIl19--d488db9c924687bee43406dd7c1c9bd24d356d5a".to_string());
    }

    #[test]
    fn to_zip_string() {
        let cookie = Cookie::<Base64<Zip<Json>>>::new("super secret");

        let session = Session {
            session_id: "68a1064d819ac5e9d4a0370131d5a79ce688a3677faf15a6cc4fc56ab486423a".into(),
            foo: "bar".into(),
            baz: 123,
            qux: vec!["a".into(), "b".into(), "c".into()],
        };

        assert_eq!(cookie.to_string(&session).unwrap(), "eJwVjEsKAjEQBe%2FS61mkJ0nncxUReekkMBuDBkEU725mUVCLor4025zHuN%2BOSpkkgo24GjlBfUvVwdhg2HL1CEmbxAgrIXR09hBV19ULiovidgvaqI%2BxRgXP5QUfyrzbjR6vN%2BULnUFZKF1%2Ff5LhIi8%3D--712024e9d801a59c1761cc622731a10d86a50c2a".to_string());
    }
}
