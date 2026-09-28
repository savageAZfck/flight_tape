#![no_main]
use libfuzzer_sys::fuzz_target;
use flight_tape::frame::{decode_hash, genesis_hash, Frame};

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        if let Ok(f) = serde_json::from_str::<Frame>(s) {
            let _ = f.verify(&genesis_hash());
            let _ = decode_hash(&f.hash);
        }
    }
});
