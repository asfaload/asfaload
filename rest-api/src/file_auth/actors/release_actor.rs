use super::git_actor::{CommitFile, GitActor};
use crate::file_auth::release_types::{
    BackendReleaseInfo, ReleaseAdder, ReleaseError, ReleaseUrlError,
};
use crate::file_auth::releasers::ReleaseAdders;
use aggregate_signature::get_authorized_signers_for_file;
use common::SignedFileLoader;
use common::errors::AggregateSignatureError;
use features_lib::{AsfaloadPublicKeyTrait, SignedFileWithKindTrait};
use forge_release::common::{ReleaseHandlingError, ReleaseInfo};
use forge_release::github::{ClientProvidedData, GithubReleaseInfo};
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
    pub release_info: GithubReleaseInfo,
    pub request_id: String,
    pub client_provided_data: ClientProvidedData,
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
            release_info = %msg.release_info,
            "Processing release"
        );

        // The release adder validates the client provided data during its initialisation.
        // The release adder validates the client provided data because:
        // - we have access to all data we need such as the config to create a github
        // fetcher.
        // - validation of the data depends of the forge we will interact with, and so only a
        // specific release adder can do the validation.
        let adder = ReleaseAdders::new(
            &msg.release_info
                .to_url()
                .map_err(|e| ApiError::InvalidReleaseUrl(e.to_string()))?,
            msg.client_provided_data,
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
                // Retrieval and parsing of the release themselves are
                // server-side problems; invalid data or urls are
                // user-provided and lead to a bad request.
                ReleaseError::Generic(e) => match e {
                    ReleaseHandlingError::FetchError(_) | ReleaseHandlingError::ParseError(_) => {
                        ApiError::InternalServerError(e.to_string())
                    }
                    ReleaseHandlingError::InvalidData(_)
                    | ReleaseHandlingError::InvalidUrl(_)
                    | ReleaseHandlingError::Generic(_) => {
                        ApiError::InvalidRequestBody(e.to_string())
                    }
                },
                ReleaseError::SerdeError(e) => ApiError::InternalServerError(e.to_string()),
            }
        })?;

        let index_path = adder.index_path().await?;
        let authorised_signers =
            get_authorized_signers_for_file(index_path.clone()).map_err(|e| {
                tracing::error!(
                    actor = %ACTOR_NAME,
                    error = %e,
                    index_path = %index_path,
                    "Failed to get authorised signers for index path"
                );
                match e {
                    // A missing signers config for the project is a
                    // client-side configuration problem, reported as a bad
                    // request. Other errors are server-side faults.
                    AggregateSignatureError::Io(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        ApiError::NoActiveSignersFile
                    }
                    _ => ApiError::Generic(
                        "Could not retrieve authorised signers for index path".to_string(),
                    ),
                }
            })?;
        if !authorised_signers.contains(adder.pub_key()) {
            tracing::error!(
                actor = %ACTOR_NAME,
                index_path = %index_path,
                signing_key = %adder.pub_key().to_base64(),
                "Submitter key not found in authorised signers for path"
            );

            return Err(ApiError::NotAuthorized(
                "Signing key is not present in authorised keys.".into(),
            ));
        }

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
        let index_signed_file = SignedFileLoader::load(index_file_path.clone())?;
        let sig_with_state = index_signed_file
            .add_signature(adder.signature().clone(), adder.pub_key().clone())
            .map_err(|e| {
                tracing::error!(
                    request_id = %msg.request_id,
                    actor = %ACTOR_NAME,
                    error = %e,
                    "Could not create empty aggregate signature for index file"
                );
                ApiError::Generic(format!(
                    "Problem registering signature of release to be registered:{}",
                    e
                ))
            })?;
        info!(
            request_id = %msg.request_id,
            actor = %ACTOR_NAME,
            index_path = %index_file_path,
            sig_complete = %sig_with_state.is_complete(),
            "Release registration signature registered",
        );

        let commit_msg = CommitFile {
            file_paths: vec![release_info.release_path().clone()],
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
