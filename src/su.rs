use std::env;
use std::fs::{self, OpenOptions};
use std::io;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::error::{CopyfailError, Result};

pub fn resolve_su() -> Result<PathBuf> {
    resolve_su_with(|path| path.exists(), env::var_os("PATH"))
}

fn resolve_su_with<F>(exists: F, path_env: Option<std::ffi::OsString>) -> Result<PathBuf>
where
    F: Fn(&Path) -> bool,
{
    let preferred = Path::new("/usr/bin/su");
    if exists(preferred) {
        return Ok(preferred.to_path_buf());
    }

    if let Some(path_env) = path_env {
        for dir in env::split_paths(&path_env) {
            let candidate = dir.join("su");
            if exists(&candidate) {
                return Ok(candidate);
            }
        }
    }

    Err(CopyfailError::SuNotFound)
}

pub fn backup_su_binary(src: &Path, dst: &Path) -> Result<()> {
    let metadata = fs::metadata(src)?;
    let contents = fs::read(src)?;

    let mut output = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(dst)?;

    use std::io::Write;
    output.write_all(&contents)?;
    output.sync_all()?;
    drop(output);

    let permissions = fs::Permissions::from_mode(metadata.mode());
    fs::set_permissions(dst, permissions)?;

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

    let dst_cstr = std::ffi::CString::new(dst.as_os_str().as_encoded_bytes())
        .map_err(|err| CopyfailError::Io(io::Error::new(io::ErrorKind::InvalidInput, err)))?;

    let rc = unsafe { libc::utimensat(libc::AT_FDCWD, dst_cstr.as_ptr(), times.as_ptr(), 0) };
    if rc != 0 {
        return Err(CopyfailError::SyscallFailure {
            operation: "utimensat",
            source: io::Error::last_os_error(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{backup_su_binary, resolve_su_with};
    use std::ffi::OsString;
    use std::fs;
    use std::io;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("copyfail-rs-{label}-{nanos}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn prefers_usr_bin_su() {
        let resolved = resolve_su_with(
            |path| path == Path::new("/usr/bin/su") || path == Path::new("/bin/su"),
            Some(OsString::from("/bin:/usr/local/bin")),
        )
        .unwrap();
        assert_eq!(resolved, PathBuf::from("/usr/bin/su"));
    }

    #[test]
    fn falls_back_to_path_lookup() {
        let resolved = resolve_su_with(
            |path| path == Path::new("/opt/tools/su"),
            Some(OsString::from("/usr/local/bin:/opt/tools")),
        )
        .unwrap();
        assert_eq!(resolved, PathBuf::from("/opt/tools/su"));
    }

    #[test]
    fn backup_preserves_contents_mode_and_timestamps() {
        let dir = temp_dir("backup");
        let src = dir.join("su-src");
        let dst = dir.join("su-backup");

        fs::write(&src, b"original su bytes").unwrap();
        fs::set_permissions(&src, fs::Permissions::from_mode(0o6755)).unwrap();

        let atime = libc::timespec {
            tv_sec: 1_700_000_000,
            tv_nsec: 123_000_000,
        };
        let mtime = libc::timespec {
            tv_sec: 1_700_000_100,
            tv_nsec: 456_000_000,
        };
        let src_cstr = std::ffi::CString::new(src.as_os_str().as_encoded_bytes()).unwrap();
        let rc = unsafe {
            libc::utimensat(
                libc::AT_FDCWD,
                src_cstr.as_ptr(),
                [atime, mtime].as_ptr(),
                0,
            )
        };
        assert_eq!(rc, 0, "utimensat failed: {}", io::Error::last_os_error());

        backup_su_binary(&src, &dst).unwrap();

        assert_eq!(fs::read(&dst).unwrap(), b"original su bytes");

        let src_meta = fs::metadata(&src).unwrap();
        let dst_meta = fs::metadata(&dst).unwrap();

        assert_eq!(dst_meta.mode() & 0o7777, src_meta.mode() & 0o7777);
        assert_eq!(dst_meta.mtime(), src_meta.mtime());
        assert_eq!(dst_meta.mtime_nsec(), src_meta.mtime_nsec());
        assert_eq!(dst_meta.atime(), src_meta.atime());
        assert_eq!(dst_meta.atime_nsec(), src_meta.atime_nsec());

        let _ = fs::remove_dir_all(dir);
    }
}
