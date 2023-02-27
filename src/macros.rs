macro_rules! validity_checks {
    () => {
        /// Check if this is valid
        pub fn is_valid(&self) -> Choice {
            !self.0.is_identity() | !self.0.is_on_curve()
        }

        /// Check if this is invalid
        pub fn is_invalid(&self) -> Choice {
            self.0.is_identity() | !self.0.is_on_curve()
        }
    };
}

macro_rules! bytes_impl {
    ($affine:ident, $projective:ident) => {
        /// Get the byte representation
        pub fn to_bytes(self) -> [u8; Self::BYTES] {
            self.0.to_affine().to_compressed()
        }

        /// Convert a big-endian representation
        pub fn from_bytes(bytes: &[u8; Self::BYTES]) -> CtOption<Self> {
            $affine::from_compressed(bytes).map(|p| Self($projective::from(&p)))
        }
    };
}

macro_rules! cond_select_impl {
    ($name:ident, $projective:ident) => {
        impl subtle::ConditionallySelectable for $name {
            fn conditional_select(a: &Self, b: &Self, choice: Choice) -> Self {
                Self($projective::conditional_select(&a.0, &b.0, choice))
            }
        }
    };
}

macro_rules! serde_impl {
    ($name:ident, $projective:ident) => {
        impl serde::Serialize for $name {
            fn serialize<S>(&self, s: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                self.0.serialize(s)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(d: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let p = $projective::deserialize(d)?;
                Ok(Self(p))
            }
        }
    };
}

macro_rules! display_one_impl {
    ($name:ident) => {
        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

macro_rules! display_size_impl {
    ($name:ident, $size:expr) => {
        impl core::fmt::Display for $name {
            #[allow(unsafe_code)]
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                const HEX_BYTES: usize = $size * 2;
                let mut hex_bytes = [0u8; HEX_BYTES];
                hex::encode_to_slice(&self.0 .0, &mut hex_bytes).unwrap();
                let output = unsafe { core::str::from_utf8_unchecked(&hex_bytes) };
                write!(f, "{}", output)
            }
        }
    };
}
