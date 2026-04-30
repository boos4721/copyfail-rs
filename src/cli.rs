use std::path::PathBuf;

use clap::Parser;

#[derive(Debug, Parser, PartialEq, Eq)]
#[command(
    name = "copyfail-rs",
    about = "Rust implementation of CVE-2026-31431 (copy-fail). Includes a safe preflight mode for target inspection.",
    after_help = "Use --check to inspect the resolved su target without attempting overwrite or exec."
)]
pub struct Cli {
    /// path to copy the su binary to before overwriting
    #[arg(long)]
    pub backup: Option<PathBuf>,

    /// command to run as root; full path required
    #[arg(long = "exec")]
    pub exec: Option<PathBuf>,

    /// safe preflight mode: inspect the resolved su target and exit
    #[arg(long)]
    pub check: bool,
}

#[cfg(test)]
mod tests {
    use super::Cli;
    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn parses_default_values() {
        let cli = Cli::parse_from(["copyfail-rs"]);
        assert_eq!(cli.backup, None);
        assert_eq!(cli.exec, None);
        assert!(!cli.check);
    }

    #[test]
    fn parses_backup_path() {
        let cli = Cli::parse_from(["copyfail-rs", "--backup", "/tmp/su"]);
        assert_eq!(cli.backup, Some(PathBuf::from("/tmp/su")));
        assert_eq!(cli.exec, None);
    }

    #[test]
    fn parses_exec_path() {
        let cli = Cli::parse_from(["copyfail-rs", "--exec", "/abs/path"]);
        assert_eq!(cli.backup, None);
        assert_eq!(cli.exec, Some(PathBuf::from("/abs/path")));
    }

    #[test]
    fn parses_check_flag() {
        let cli = Cli::parse_from(["copyfail-rs", "--check"]);
        assert_eq!(cli.backup, None);
        assert_eq!(cli.exec, None);
        assert!(cli.check);
    }
}
