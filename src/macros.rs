macro_rules! impl_from_derivatives_generic {
    ($name:ident) => {
        impl<C: BlsSignatureImpl> From<$name<C>> for Vec<u8> {
            fn from(value: $name<C>) -> Self {
                Vec::from(&value)
            }
        }

        impl<C: BlsSignatureImpl> TryFrom<Vec<u8>> for $name<C> {
            type Error = BlsError;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(&value)
            }
        }

        impl<C: BlsSignatureImpl> TryFrom<&Vec<u8>> for $name<C> {
            type Error = BlsError;

            fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(value.as_slice())
            }
        }

        impl<C: BlsSignatureImpl> TryFrom<Box<[u8]>> for $name<C> {
            type Error = BlsError;

            fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
                Self::try_from(value.as_ref())
            }
        }
    };
}

macro_rules! impl_from_derivatives {
    ($name:ident) => {
        impl From<$name> for Vec<u8> {
            fn from(value: $name) -> Self {
                Vec::from(&value)
            }
        }

        impl TryFrom<Vec<u8>> for $name {
            type Error = BlsError;

            fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(&value)
            }
        }

        impl TryFrom<&Vec<u8>> for $name {
            type Error = BlsError;

            fn try_from(value: &Vec<u8>) -> Result<Self, Self::Error> {
                Self::try_from(value.as_slice())
            }
        }

        impl TryFrom<Box<[u8]>> for $name {
            type Error = BlsError;

            fn try_from(value: Box<[u8]>) -> Result<Self, Self::Error> {
                Self::try_from(value.as_ref())
            }
        }
    };
}
