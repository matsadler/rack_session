use std::{
    error::Error as StdError,
    fmt,
    io::{Read, Write},
    marker::PhantomData,
};

use flate2::{read::ZlibDecoder, write::ZlibEncoder, Compression};
use serde::{de::DeserializeOwned, Serialize};

pub trait BinaryCoder {
    type DecodeError;
    type EncodeError;

    fn from_slice<T>(input: &[u8]) -> Result<T, Self::DecodeError>
    where
        T: DeserializeOwned;

    fn to_vec<T>(value: &T) -> Result<Vec<u8>, Self::EncodeError>
    where
        T: Serialize;
}

pub unsafe trait Coder: BinaryCoder {
    fn from_str<T>(s: &str) -> Result<T, Self::DecodeError>
    where
        T: DeserializeOwned,
    {
        Self::from_slice(s.as_bytes())
    }

    fn to_string<T>(value: &T) -> Result<String, Self::EncodeError>
    where
        T: Serialize,
    {
        let vec = Self::to_vec(value)?;
        // this trait is marked unsafe and only implemented when
        // <Self as BinaryCoder>::to_vec() is guaranteed to return only valid
        // utf-8, making this safe
        Ok(unsafe { String::from_utf8_unchecked(vec) })
    }
}

/// Coder for Base64 encoded cookies.
pub struct Base64<C> {
    phantom: PhantomData<C>,
}

#[derive(Debug)]
pub enum Base64Error {
    Base64(base64::DecodeError),
    Json(serde_json::Error),
    Zip(ZipError),
}

impl fmt::Display for Base64Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Base64Error::Base64(e) => e.fmt(f),
            Base64Error::Json(e) => e.fmt(f),
            Base64Error::Zip(e) => e.fmt(f),
        }
    }
}

impl From<base64::DecodeError> for Base64Error {
    fn from(error: base64::DecodeError) -> Self {
        Base64Error::Base64(error)
    }
}

impl From<serde_json::Error> for Base64Error {
    fn from(error: serde_json::Error) -> Self {
        Base64Error::Json(error)
    }
}

impl From<ZipError> for Base64Error {
    fn from(error: ZipError) -> Self {
        Base64Error::Zip(error)
    }
}

impl StdError for Base64Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Base64Error::Base64(e) => Some(e),
            Base64Error::Json(e) => Some(e),
            Base64Error::Zip(e) => Some(e),
        }
    }
}

impl<C> BinaryCoder for Base64<C>
where
    C: BinaryCoder,
    Base64Error: From<C::DecodeError>,
    Base64Error: From<C::EncodeError>,
{
    type DecodeError = Base64Error;
    type EncodeError = Base64Error;

    fn from_slice<T>(input: &[u8]) -> Result<T, Self::DecodeError>
    where
        T: DeserializeOwned,
    {
        let data = input
            .iter()
            .copied()
            .filter(|&c| c != b'\n')
            .collect::<Vec<_>>();
        let decoded = base64::decode(data)?;
        Ok(C::from_slice(&decoded)?)
    }

    fn to_vec<T>(value: &T) -> Result<Vec<u8>, Self::EncodeError>
    where
        T: Serialize,
    {
        Ok(base64::encode(C::to_vec(value)?).into_bytes())
    }
}

// Base64 is always valid utf-8, so it's safe to implement Coder
unsafe impl<C> Coder for Base64<C>
where
    C: BinaryCoder,
    Base64Error: From<C::DecodeError>,
    Base64Error: From<C::EncodeError>,
{
}

/// Coder for Zipped cookies.
pub struct Zip<C> {
    phantom: PhantomData<C>,
}

#[derive(Debug)]
pub enum ZipError {
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for ZipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ZipError::Io(e) => e.fmt(f),
            ZipError::Json(e) => e.fmt(f),
        }
    }
}

impl From<std::io::Error> for ZipError {
    fn from(error: std::io::Error) -> Self {
        ZipError::Io(error)
    }
}

impl From<serde_json::Error> for ZipError {
    fn from(error: serde_json::Error) -> Self {
        ZipError::Json(error)
    }
}

impl StdError for ZipError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            ZipError::Io(e) => Some(e),
            ZipError::Json(e) => Some(e),
        }
    }
}

impl<C> BinaryCoder for Zip<C>
where
    C: BinaryCoder,
    ZipError: From<C::DecodeError>,
    ZipError: From<C::EncodeError>,
{
    type DecodeError = ZipError;
    type EncodeError = ZipError;

    fn from_slice<T>(input: &[u8]) -> Result<T, Self::DecodeError>
    where
        T: DeserializeOwned,
    {
        let mut deflater = ZlibDecoder::new(input);
        let mut decoded = Vec::new();
        deflater.read_to_end(&mut decoded)?;
        Ok(C::from_slice(&decoded)?)
    }

    fn to_vec<T>(value: &T) -> Result<Vec<u8>, Self::EncodeError>
    where
        T: Serialize,
    {
        let mut e = ZlibEncoder::new(Vec::new(), Compression::default());
        e.write_all(&C::to_vec(value)?)?;
        Ok(e.finish()?)
    }
}

/// Coder for JSON encoded cookies.
pub enum Json {}

impl BinaryCoder for Json {
    type DecodeError = serde_json::Error;
    type EncodeError = serde_json::Error;

    fn from_slice<T>(input: &[u8]) -> Result<T, Self::DecodeError>
    where
        T: DeserializeOwned,
    {
        Ok(serde_json::from_slice(input)?)
    }

    fn to_vec<T>(value: &T) -> Result<Vec<u8>, Self::EncodeError>
    where
        T: Serialize,
    {
        Ok(serde_json::to_vec(value)?)
    }
}

// JSON is always valid utf-8, so it's safe to implement Coder
unsafe impl Coder for Json {}
