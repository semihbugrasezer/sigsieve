#![no_main]
libfuzzer_sys::fuzz_target!(|data: &[u8]| sigsieve::fuzzing::upstream_reply(data));
