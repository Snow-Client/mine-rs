use crate::*;
use std::convert::Infallible;

mod bool;
mod cow;
mod num;
mod slice;
mod str;
mod string;
mod uuid;
mod vec;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    IntError(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    Uuid(#[from] ::uuid::Error),
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
    #[error("unexpected end of slice")]
    UnexpectedEndOfSlice,
    #[error("invalid id")]
    InvalidId,
}

impl From<Infallible> for Error {
    fn from(i: Infallible) -> Self {
        match i {}
    }
}

pub trait Decode<'dec>: Sized {
    fn decode(cursor: &mut Cursor<&'dec [u8]>) -> Result<Self>;
}
