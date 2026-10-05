pub mod artifact_info;
mod backend;
pub mod constants;
mod download;
mod error;
pub mod signers_chain;
pub mod signers_metadata;
mod types;
mod verification;

pub use download::download_file_with_verification;
pub use error::{AsfaloadLibResult, ClientLibError};
pub use signers_chain::{SignersChainResult, verify_signers_chain};
pub use signers_metadata::verify_signers_file_matches_metadata_source;
pub use types::{ComputedHash, DownloadCallbacks, DownloadResult, RevocationDetectedArgs};
