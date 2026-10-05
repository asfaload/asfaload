use super::git_actor::{CommitFile, GitActor};
use crate::file_auth::release_types::{
    BackendReleaseInfo, ReleaseAdder, ReleaseError, ReleaseInfo, ReleaseUrlError,
};
use crate::file_auth::releasers::ReleaseAdders;
use crate::helpers::create_empty_aggregate_signature;
use kameo::message::Context;
use kameo::prelude::{Actor, Message};
use rest_api_types::errors::ApiError;
use rest_api_types::path_validation::NormalisedPaths;
use tracing::info;
use uuid::Uuid;

const ACTOR_NAME: &str = "release_actor";
pub struct ReleaseActor {
    git_actor: kameo::actor::ActorRef<GitActor>,
    config: crate::config::AppConfig,
}

pub struct ProcessRelease {
    pub release_url: url::Url,
    pub request_id: String,
}

pub struct RegisterResult {
    pub index_file_path: NormalisedPaths,
}

impl Actor for ReleaseActor {
    type Args = (kameo::actor::ActorRef<GitActor>, crate::config::AppConfig);
    type Error = ApiError;

    async fn on_start(
        args: Self::Args,
        _actor_ref: kameo::prelude::ActorRef<Self>,
    ) -> Result<Self, Self::Error> {
        tracing::info!(actor = ACTOR_NAME, "Release actor starting");

        Ok(Self {
            git_actor: args.0,
            config: args.1,
        })
    }
}

impl Message<ProcessRelease> for ReleaseActor {
    type Reply = Result<RegisterResult, ApiError>;

    async fn handle(
        &mut self,
        msg: ProcessRelease,
        ctx: &mut Context<Self, Self::Reply>,
    ) -> Self::Reply {
        self.process_release(msg, ctx).await
    }
}

impl ReleaseActor {
    async fn process_release(
        &self,
        msg: ProcessRelease,
        _ctx: &mut Context<Self, Result<RegisterResult, ApiError>>,
    ) -> Result<RegisterResult, ApiError> {
        info!(
            request_id = %msg.request_id,
            url = %msg.release_url,
            "Processing release"
        );

        let adder = ReleaseAdders::new(
            &msg.release_url,
            self.config.git_repo_path.clone(),
            &self.config,
        )
        .await
        .map_err(|e| {
            tracing::error!(
                actor = %ACTOR_NAME,
                error = %e,
                "Failed to initialise GithubReleaseAdder"
            );
            match e {
                ReleaseError::ReleaseUrlError(url_error) => match url_error {
                    ReleaseUrlError::UnsupportedPlatform(platform) => {
                        ApiError::UnsupportedReleasePlatform(platform)
                    }
                    ReleaseUrlError::InvalidFormat(msg) => ApiError::InvalidReleaseUrl(msg),
                    ReleaseUrlError::MissingTag => {
                        ApiError::InvalidReleaseUrl("Missing tag in release URL".to_string())
                    }
                    ReleaseUrlError::MissingComponent(msg) => ApiError::InvalidReleaseUrl(msg),
                },
                ReleaseError::ClientError(e) => ApiError::InternalServerError(e),
            }
        })?;

        let release_info = adder.release_info();

        info!(
            request_id = %msg.request_id,
            actor = %ACTOR_NAME,
            owner = %release_info.owner(),
            repo = %release_info.repo(),
            tag = %release_info.tag(),
            release_path = %release_info.release_path().relative_path().display(),
            "Extracted release info"
        );

        let index_file_path = adder.create_index().await.inspect_err(|e| {
            tracing::error!(
            request_id = %msg.request_id,
            actor = %ACTOR_NAME,
            error = %e,
            index_path = %release_info.release_path(),
            "Failed to create index file"

            );
        })?;
        info!(
            request_id = %msg.request_id,
            actor = %ACTOR_NAME,
            index_path = %index_file_path,
            "Index file written",
        );

        // Create empty aggregate signature for the index file
        let signature_file_path = create_empty_aggregate_signature(&index_file_path)
            .await
            .map_err(|e| {
                tracing::error!(
                    request_id = %msg.request_id,
                    actor = %ACTOR_NAME,
                    error = %e,
                    "Could not create empty aggregate signature for index file"
                );
                e
            })?;

        info!(
            request_id = %msg.request_id,
            actor = %ACTOR_NAME,
            signature_path = %signature_file_path,
            "Empty aggregate signature file created",
        );

        let commit_msg = CommitFile {
            file_paths: vec![index_file_path.clone(), signature_file_path],
            commit_message: format!(
                "Add index and signature for {}/{}/{}",
                release_info.owner(),
                release_info.repo(),
                release_info.tag()
            ),
            request_id: Uuid::new_v4().to_string(),
        };

        self.git_actor
            .ask(commit_msg)
            .await
            .map_err(|e| ApiError::InternalServerError(format!("Failed to commit file: {}", e)))?;

        Ok(RegisterResult { index_file_path })
    }
}
