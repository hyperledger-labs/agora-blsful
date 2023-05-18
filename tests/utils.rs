use rand_core::SeedableRng;

pub const TEST_ID: &'static [u8] = b"super id";
pub const TEST_MSG: &'static [u8] = b"signatures_work";
pub const BAD_MSG: &'static [u8] = b"bad message";


pub struct MockRng(rand_xorshift::XorShiftRng);

impl SeedableRng for MockRng {
    type Seed = [u8; 16];

    fn from_seed(seed: Self::Seed) -> Self {
        Self(rand_xorshift::XorShiftRng::from_seed(seed))
    }
}

impl rand_core::CryptoRng for MockRng {}

impl rand_core::RngCore for MockRng {
    fn next_u32(&mut self) -> u32 {
        self.0.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.0.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.0.fill_bytes(dest)
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl Default for MockRng {
    fn default() -> Self {
        Self(rand_xorshift::XorShiftRng::from_seed([7u8; 16]))
    }
}