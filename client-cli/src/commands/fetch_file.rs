use std::path::PathBuf;

use common::base64_for_vec_u8;
use serde::Serialize;
use tokio::{fs::File, io::AsyncWriteExt};

use crate::error::{ClientCliError, Result};

#[derive(Serialize)]
struct FetchFileJsonOutput {
    output: Option<PathBuf>,
    // base64 encoded content of fetched file
    base64_content: String,
}

async fn maybe_write_content_to_file(
    content: &[u8],
    output_path: &Option<PathBuf>,
) -> Result<bool> {
    if let Some(output_path) = output_path {
        // Write file content
        let mut file = File::create_new(output_path).await?;
        file.write_all(content).await?;
        file.flush().await?;
        Ok(true)
    } else {
        Ok(false)
    }
}
pub async fn handle_fetch_file(
    path: &str,
    output_path: &Option<PathBuf>,
    backend_url: &str,
    json: bool,
) -> Result<()> {
    let content = admin_lib::v1::Client::new(backend_url)
        .fetch_file(path)
        .await?;
    if json {
        maybe_write_content_to_file(&content, output_path).await?;
        let base64_content = base64_for_vec_u8(&content);
        let json_data = FetchFileJsonOutput {
            output: output_path.clone(),
            base64_content,
        };
        let output_string = serde_json::to_string(&json_data)?;
        println!("{}", output_string);
        Ok(())
    } else {
        let written_to_disk = maybe_write_content_to_file(&content, output_path).await?;
        // only send to stdout if we don't write it to disk
        if !written_to_disk {
            let output = String::from_utf8(content).map_err(|e| {
            ClientCliError::InvalidInput(format!(
                "Could not convert file content to string to print it on stdout. Save to file or request json output: {}",
                e
            ))
        })?;
            print!("{}", output);
        }
        Ok(())
    }
}
