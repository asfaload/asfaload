use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// Default backend API URL
pub const DEFAULT_BACKEND: &str = "https://backend.asfaload.com";

// helpers for clap

#[derive(clap::Args, Debug)]
#[group(multiple = false)]
pub struct PasswordArgs {
    /// Password for the key
    #[arg(long, short)]
    pub password: Option<String>,

    /// Path to a file containing the password
    #[arg(long, short = 'P', env = "ASFALOAD_PASSWORD_FILE")]
    pub password_file: Option<PathBuf>,

    /// Command printing the password to its stdout
    #[arg(long, short = 'c', env = "ASFALOAD_PASSWORD_COMMAND")]
    pub password_command: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct SecretKeyArgs {
    /// Path to your secret key file (asfaload or OpenSSH ed25519)
    #[arg(short = 'K', long, env = "ASFALOAD_SECRET_KEY")]
    pub secret_key: PathBuf,
}

#[derive(clap::Args, Debug)]
pub struct BackendUrlArgs {
    /// Backend API URL (optional, defaults to DEFAULT_BACKEND)
    #[arg(short = 'u', long, env = "ASFALOAD_BACKEND_URL")]
    pub backend_url: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct DigestFilter {
    /// Only consider pending files with this sha512 checksum
    #[arg(long, visible_alias = "df")]
    pub digest_filter: Option<String>,
}

#[derive(clap::Args, Debug)]
pub struct JsonArgs {
    /// Output results as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::ValueEnum, Clone, Debug)]
pub enum ForgeType {
    Github,
    Gitlab,
    Fileserver,
}

impl ForgeType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ForgeType::Github => "github",
            ForgeType::Gitlab => "gitlab",
            ForgeType::Fileserver => "fileserver",
        }
    }
}

#[derive(clap::Args, Debug)]
pub struct ForgeTypeArgs {
    /// Override forge type detection (github, gitlab, fileserver)
    #[arg(long = "type")]
    pub forge_type: Option<ForgeType>,
}

#[derive(Parser, Debug)]
#[command(name = "asfaload-cli")]
#[command(about = "A CLI client for Asfaload operations")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Create a new key pair in the directory of your choice
    NewKeys {
        /// Name of the key (from which filenames for secret and public keys are derived)
        #[arg(long, short)]
        name: String,

        /// Directory to store the key
        #[arg(long, short = 'd', default_value = ".")]
        output_dir: PathBuf,

        #[command(flatten)]
        password_args: PasswordArgs,
        ///
        /// Accept week passwords, bypassing password strength validations (INSECURE!)
        #[arg(long)]
        accept_weak_password: bool,

        #[command(flatten)]
        json_args: JsonArgs,
    },

    /// Get information to share your key
    ShareKey {
        /// Path to the public key (asfaload or ssh ed25519).
        #[arg(long, short = 'k')]
        public_key: PathBuf,

        /// Print only the key
        #[arg(long, short, conflicts_with = "json")]
        raw: bool,

        #[command(flatten)]
        json_args: JsonArgs,
    },
    /// Operations related to signers files
    NewSignersFile {
        /// Artifact signer public key as base64 string (can be repeated)
        #[arg(long, short, value_name = "PUB_KEY")]
        artifact_signer: Vec<String>,

        /// File with artifact signers public keys, one per line
        #[arg(long, visible_alias = "af", value_name = "FILE_PATH")]
        artifact_signers_file: Vec<PathBuf>,

        /// Threshold for artifact signers
        #[arg(long, short = 'A')]
        artifact_threshold: u32,

        /// Admin public key string as base64 string (can be repeated)
        #[arg(long, short = 'd', value_name = "PUB_KEY")]
        admin_key: Vec<String>,

        /// File with admins public keys, one per line
        #[arg(long, visible_alias = "df", value_name = "FILE_PATH")]
        admin_keys_file: Vec<PathBuf>,

        /// Threshold for admin keys (required if admin keys are provided)
        #[arg(long, short = 'D')]
        admin_threshold: Option<u32>,

        /// Master public key string as base64 string (can be repeated)
        #[arg(long, short, value_name = "PUB_KEY")]
        master_key: Vec<String>,

        /// File with masters public keys, one per line
        #[arg(long, visible_alias = "mf", value_name = "FILE_PATH")]
        master_keys_file: Vec<PathBuf>,

        /// Threshold for master keys (required if master keys are provided)
        #[arg(long, short = 'M')]
        master_threshold: Option<u32>,

        /// Revocation public key string as base64 string (can be repeated)
        #[arg(long, short, value_name = "PUB_KEY")]
        revocation_key: Vec<String>,

        /// File with revocation public keys, one per line
        #[arg(long, visible_alias = "rf", value_name = "FILE_PATH")]
        revocation_keys_file: Vec<PathBuf>,

        /// Threshold for revocation keys (required if revocation keys are provided)
        #[arg(long, short = 'R')]
        revocation_threshold: Option<u32>,

        /// Path to the signers file to be created; if omitted, writes to stdout (required with --json)
        #[arg(long, short, required_if_eq("json", "true"))]
        output_file: Option<PathBuf>,

        #[command(flatten)]
        json_args: JsonArgs,
    },
    GetDigest {
        file: String,

        #[command(flatten)]
        json_args: JsonArgs,
    },
    /// List files requiring your signature from the backend
    ListPending {
        #[command(flatten)]
        secret_key_args: SecretKeyArgs,

        #[command(flatten)]
        password_args: PasswordArgs,

        #[command(flatten)]
        backend_url_args: BackendUrlArgs,

        #[command(flatten)]
        digest_filter: DigestFilter,

        #[command(flatten)]
        json_args: JsonArgs,
    },

    /// Sign a pending file (fetch, sign, submit)
    SignPending {
        /// Path to the pending file (relative path in mirror). Prompted for select if missing.
        #[arg(requires = "digest")]
        file_path: Option<String>,

        #[arg(long, requires = "file_path")]
        digest: Option<String>,

        #[command(flatten)]
        secret_key_args: SecretKeyArgs,

        #[command(flatten)]
        password_args: PasswordArgs,

        #[command(flatten)]
        backend_url_args: BackendUrlArgs,

        #[command(flatten)]
        digest_filter: DigestFilter,

        #[command(flatten)]
        json_args: JsonArgs,
    },

    /// Check signature collection status for a file
    SignatureStatus {
        /// Path to the file (relative path in mirror)
        file_path: String,

        #[command(flatten)]
        secret_key_args: SecretKeyArgs,

        #[command(flatten)]
        password_args: PasswordArgs,

        #[command(flatten)]
        backend_url_args: BackendUrlArgs,

        #[command(flatten)]
        json_args: JsonArgs,
    },

    /// Register a repository with the backend
    RegisterRepo {
        /// URL to the signers file (e.g., https://raw.githubusercontent.com/owner/repo/branch/asfaload.signers/index.json)
        signers_file_url: String,

        #[command(flatten)]
        secret_key_args: SecretKeyArgs,

        #[command(flatten)]
        password_args: PasswordArgs,

        #[command(flatten)]
        backend_url_args: BackendUrlArgs,

        #[command(flatten)]
        json_args: JsonArgs,
    },

    /// Register assets with the backend (GitHub release or checksums files)
    RegisterAssets {
        /// GitHub release URL (mutually exclusive with --csum-file)
        #[arg(long, conflicts_with = "csum_file")]
        github_release_url: Option<String>,

        /// Checksums file URL (repeatable, mutually exclusive with --github-release-url)
        #[arg(long, conflicts_with = "github_release_url")]
        csum_file: Vec<String>,

        #[command(flatten)]
        secret_key_args: SecretKeyArgs,

        #[command(flatten)]
        password_args: PasswordArgs,

        #[command(flatten)]
        backend_url_args: BackendUrlArgs,

        #[command(flatten)]
        json_args: JsonArgs,
    },

    /// Propose an update to an existing signers file
    UpdateSigners {
        /// URL to the new signers file on the forge
        signers_file_url: String,

        #[command(flatten)]
        secret_key_args: SecretKeyArgs,

        #[command(flatten)]
        password_args: PasswordArgs,

        #[command(flatten)]
        backend_url_args: BackendUrlArgs,

        #[command(flatten)]
        json_args: JsonArgs,
    },

    /// Revoke a signed file on the mirror
    Revoke {
        /// Relative path to the signed file on the mirror
        file_path: String,

        #[command(flatten)]
        secret_key_args: SecretKeyArgs,

        #[command(flatten)]
        password_args: PasswordArgs,

        #[command(flatten)]
        backend_url_args: BackendUrlArgs,

        #[command(flatten)]
        json_args: JsonArgs,
    },

    /// Ping the backend, optionally testing your credentials
    Ping {
        // NOTE: this does not use SecretKeyArgs to not make it a mandatory flag.
        /// Path to your secret key file; when given, the ping request is
        /// authenticated (asfaload or OpenSSH ed25519)
        #[arg(short = 'K', long, env = "ASFALOAD_SECRET_KEY")]
        secret_key: Option<PathBuf>,

        #[command(flatten)]
        password_args: PasswordArgs,

        #[command(flatten)]
        backend_url_args: BackendUrlArgs,

        #[command(flatten)]
        json_args: JsonArgs,
    },

    /// Download a file with signature verification
    Download {
        /// URL of the file to download (e.g., https://github.com/user/repo/releases/download/v1.0.0/file.tar.gz)
        file_url: String,

        /// Output file path (optional, defaults to filename from URL)
        #[arg(short = 'o', long)]
        output: Option<PathBuf>,

        #[command(flatten)]
        backend_url_args: BackendUrlArgs,

        #[command(flatten)]
        forge_type_args: ForgeTypeArgs,
    },

    /// Validate a mirror index file against its digest sources
    CheckIndex {
        /// Path to the index file on the mirror (as displayed by list-pending)
        index_path: String,

        #[command(flatten)]
        backend_url_args: BackendUrlArgs,

        #[command(flatten)]
        json_args: JsonArgs,
    },
}

const ENV_VAR_PREFIX: &str = "ASFALOAD";
enum EnvVarKind {
    Password,
    PasswordFile,
}
impl std::fmt::Display for EnvVarKind {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let s = match self {
            EnvVarKind::Password => "password",
            EnvVarKind::PasswordFile => "password_file",
        };
        write!(f, "{}", s)
    }
}

impl Commands {
    // Fucntions to build environment variables for commands in a standard way
    fn env_var_base(&self) -> &str {
        match self {
            Self::NewSignersFile { .. } => "NEW_SIGNERS_FILE",
            Self::NewKeys { .. } => "NEW_KEYS",
            Self::ShareKey { .. } => "SHARE_KEY",
            Self::ListPending { .. } => "LIST_PENDING",
            Self::SignPending { .. } => "SIGN_PENDING",
            Self::SignatureStatus { .. } => "SIGNATURE_STATUS",
            Self::RegisterRepo { .. } => "REGISTER_REPO",
            Self::RegisterAssets { .. } => "REGISTER_ASSETS",
            Self::UpdateSigners { .. } => "UPDATE_SIGNERS",
            Self::Revoke { .. } => "REVOKE",
            Self::Ping { .. } => "PING",
            Self::Download { .. } => "DOWNLOAD",
            Self::GetDigest { .. } => "GET_DIGEST",
            Self::CheckIndex { .. } => "CHECK_INDEX",
        }
    }

    fn build_env_var(cmd: &Commands, kind: EnvVarKind) -> String {
        format!(
            "{ENV_VAR_PREFIX}_{}_{}",
            cmd.env_var_base(),
            kind.to_string().to_uppercase()
        )
    }
    pub fn password_env_var(&self) -> String {
        Self::build_env_var(self, EnvVarKind::Password)
    }

    pub fn password_file_env_var(&self) -> String {
        Self::build_env_var(self, EnvVarKind::PasswordFile)
    }

    pub fn json_output(&self) -> bool {
        match self {
            Self::NewKeys { json_args, .. }
            | Self::ShareKey { json_args, .. }
            | Self::NewSignersFile { json_args, .. }
            | Self::ListPending { json_args, .. }
            | Self::SignPending { json_args, .. }
            | Self::SignatureStatus { json_args, .. }
            | Self::RegisterRepo { json_args, .. }
            | Self::RegisterAssets { json_args, .. }
            | Self::UpdateSigners { json_args, .. }
            | Self::Revoke { json_args, .. }
            | Self::Ping { json_args, .. }
            | Self::CheckIndex { json_args, .. } => json_args.json,
            Self::GetDigest { json_args, .. } => json_args.json,
            Self::Download { .. } => false,
        }
    }
}
