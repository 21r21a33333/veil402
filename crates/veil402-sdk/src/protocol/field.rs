use core::fmt;

use ark_bn254::Fr;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::encoding;
use crate::client::Error;

/// A canonically encoded BN254 scalar field element.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct Field([u8; 32]);

impl Field {
    /// The additive identity.
    pub const ZERO: Self = Self([0; 32]);

    /// Parses a canonical 32-byte big-endian field element.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Field`] when the encoding is not canonical for BN254.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
        encoding::parse_field(&bytes).ok_or(Error::Field)?;
        Ok(Self(bytes))
    }

    /// Returns the canonical 32-byte big-endian encoding.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 32] {
        self.0
    }

    pub(crate) fn from_fr(value: Fr) -> Self {
        Self(encoding::field_bytes(value))
    }

    pub(crate) fn from_signed(value: i64) -> Self {
        let magnitude = Fr::from(value.unsigned_abs());
        Self::from_fr(if value < 0 { -magnitude } else { magnitude })
    }

    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl From<u64> for Field {
    fn from(value: u64) -> Self {
        Self::from_fr(Fr::from(value))
    }
}

impl fmt::Debug for Field {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Field(0x")?;
        for byte in self.0 {
            write!(formatter, "{byte:02x}")?;
        }
        formatter.write_str(")")
    }
}

/// A secret BN254 field element that is redacted and zeroized on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct Secret([u8; 32]);

impl Secret {
    /// Parses a secret from a canonical 32-byte big-endian field element.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Field`] when the encoding is not canonical for BN254.
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, Error> {
        Field::from_bytes(bytes)?;
        Ok(Self(bytes))
    }

    pub(crate) fn expose(&self) -> Field {
        Field(self.0)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Secret([REDACTED])")
    }
}
