use std::sync::Arc;
use std::{fs::create_dir_all, path::PathBuf};

use kameo::actor::{ActorRef, Spawn};

use rest_api_types::errors::ApiError;
use rest_api_types::git_backend::{GitBackend, Sha256GitBackend};

use crate::{
    actors::{
        nonce_cache_actor::{NONCE_CACHE_DB, NonceCacheActor},
        nonce_cleanup_actor::NonceCleanupActor,
    },
    config::GitBackendConfig,
    file_auth::actors::forge_signers_validator::ForgeProjectValidator,
    file_auth::actors::{
        git_actor::GitActor, release_actor::ReleaseActor, signature_collector::SignatureCollector,
        signers_initialiser::SignersInitialiser,
    },
};

#[derive(Clone)]
pub struct AppState {
    pub git_repo_path: PathBuf,
    pub git_backend: Arc<dyn GitBackend>,
    pub git_actor: ActorRef<GitActor>,
    pub nonce_cache_actor: ActorRef<NonceCacheActor>,
    pub nonce_cleanup_actor: ActorRef<NonceCleanupActor>,
    pub forge_project_validator: ActorRef<ForgeProjectValidator>,
    pub signers_initialiser: ActorRef<SignersInitialiser>,
    pub signature_collector: ActorRef<SignatureCollector>,
    pub release_actor: ActorRef<ReleaseActor>,
}

pub fn init_state(config: crate::config::AppConfig) -> Result<AppState, ApiError> {
    let git_repo_path = config.git_repo_path.clone();
    let git_backend: Arc<dyn GitBackend> = match config.git_backend {
        GitBackendConfig::Sha256 => Arc::new(Sha256GitBackend::new(
            &git_repo_path,
            &config.git_signing_pub_key_path,
        )),
    };

    if !git_repo_path.join(".git").exists() {
        git_backend.init().map_err(|e| {
            tracing::error!(path = %git_repo_path.display(), error = %e, "git init failed");
            e
        })?;
    }

    let git_actor = GitActor::spawn(git_backend.clone());

    // Initialize nonce cache with database path
    // FIXME: support taking the dir for the nonce db from env var
    let nonce_db_dir = git_repo_path.join(".app_cache");
    create_dir_all(&nonce_db_dir).map_err(|e| {
        tracing::error!(
            path = %nonce_db_dir.display(),
            error= %e,
            "Cannot create nonce db dir",
        );
        e
    })?;
    let nonce_db_path = git_repo_path.join(".app_cache").join(NONCE_CACHE_DB);
    let db = sled::open(nonce_db_path).map_err(|e| {
        tracing::error!(
            error = %e,
            "Problem opening nonce cache"
        );
        ApiError::NonceCacheError(format!("Could not open nonce cache: {}", e))
    })?;
    let nonce_cache_actor = NonceCacheActor::spawn(db.clone());
    let nonce_cleanup_actor = NonceCleanupActor::spawn(db.clone());

    let forge_project_validator = ForgeProjectValidator::spawn(());
    let signers_initialiser = SignersInitialiser::spawn(());
    let signature_collector = SignatureCollector::spawn(git_actor.clone());

    let release_actor = ReleaseActor::spawn((git_actor.clone(), config.clone()));

    Ok(AppState {
        git_repo_path,
        git_backend,
        git_actor,
        nonce_cache_actor,
        nonce_cleanup_actor,
        forge_project_validator,
        signers_initialiser,
        signature_collector,
        release_actor,
    })
}
