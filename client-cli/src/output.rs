use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct NewKeysOutput {
    pub public_key_path: String,
    pub public_key: String,
    pub secret_key_path: String,
}

#[derive(Debug, Serialize)]
pub struct ShareKeyOutput {
    pub public_key: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct NewSignersFileOutput {
    pub output_file: String,
    pub artifact_signers_count: usize,
    pub artifact_threshold: u32,
    pub admin_keys_count: usize,
    pub admin_threshold: Option<u32>,
    pub master_keys_count: usize,
    pub master_threshold: Option<u32>,
    pub revocation_keys_count: usize,
    pub revocation_threshold: Option<u32>,
    pub digest: String,
    pub bishop_art: String,
}

#[derive(Debug, Serialize)]
pub struct JsonError {
    pub error: String,
}

// Not derived Debug: AsfaloadIndex does not implement it and lives outside
// this crate. The struct is only ever serialized to stdout.
#[derive(Serialize)]
pub struct CheckIndexOutput {
    pub index_path: String,
    pub files_checked: usize,
    pub index: common::index_types::AsfaloadIndex,
}

#[derive(Debug, Serialize)]
pub struct CheckPendingSignersOutput {
    pub signers_path: String,
    pub retrieval_url: String,
    pub hash: String,
    pub bishop_art: String,
}
