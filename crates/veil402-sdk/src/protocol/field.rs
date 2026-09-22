use core::fmt;

use ark_bn254::Fr;
use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use super::encoding;
use crate::client::Error;

/// A canonically encoded BN254 scalar field element.
#[derive(Clone, Copy, Default, Eq, Hash, PartialEq)]
pub struct Field([u8; 32]);

impl Field {
    /// The additive identity.
    pub const ZERO: Self = Self([0; 32]);

    pub(crate) const fn from_raw_u64(value: u64) -> Self {
        let bytes = value.to_be_bytes();
        let mut field = [0_u8; 32];
        field[24] = bytes[0];
        field[25] = bytes[1];
        field[26] = bytes[2];
        field[27] = bytes[3];
        field[28] = bytes[4];
        field[29] = bytes[5];
        field[30] = bytes[6];
        field[31] = bytes[7];
        Self(field)
    }

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

    pub(crate) fn random(rng: &mut impl RngCore) -> Result<Self, Error> {
        loop {
            let mut bytes = [0_u8; 32];
            rng.try_fill_bytes(&mut bytes).map_err(|_| Error::Random)?;
            if let Ok(field) = Self::from_bytes(bytes)
                && field != Self::ZERO
            {
                return Ok(field);
            }
        }
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

    /// Generates a non-zero secret from the operating system CSPRNG.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Random`] when secure randomness is unavailable.
    pub fn random() -> Result<Self, Error> {
        Self::random_with(&mut rand::rngs::OsRng)
    }

    pub(crate) fn random_with(rng: &mut impl RngCore) -> Result<Self, Error> {
        Ok(Self(Field::random(rng)?.0))
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
