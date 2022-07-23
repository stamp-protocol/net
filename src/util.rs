use crate::error::{Error, Result};
use rasn::{self, Decode, Encode};

pub(crate) fn serialize<T: Encode>(obj: &T) -> Result<Vec<u8>> {
    Ok(rasn::der::encode(obj).map_err(|_| Error::ASNSerialize)?)
}

pub(crate) fn deserialize<T: Decode>(bytes: &[u8]) -> Result<T> {
    Ok(rasn::der::decode(bytes).map_err(|_| Error::ASNDeserialize)?)
}

