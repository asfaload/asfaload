use axum::{
    Router,
    routing::{get, post},
};

use crate::{
    auth_middleware::auth_middleware,
    handlers::{
        get_artifact_info_handler, get_artifact_signers_chain_handler, get_file_handler,
        get_files_to_sign_handler, get_pending_signatures_handler, get_revocation_handler,
        get_signature_status_handler, get_signers_handler, ping_handler, register_assets_handler,
        register_repo_handler, revoke_handler, submit_signature_handler, update_signers_handler,
    },
    state::AppState,
};

/// Build the v1 API router with all route definitions.
pub fn v1_router(app_state: AppState) -> Router<AppState> {
    let register_router = Router::new()
        .route("/register_repo", post(register_repo_handler))
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));
    let update_signers_router = Router::new()
        .route("/update_signers", post(update_signers_handler))
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));
    let pending_router = Router::new()
        .route("/pending_signatures", get(get_pending_signatures_handler))
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));
    let signature_router = Router::new()
        .route("/signatures", post(submit_signature_handler))
        .route(
            "/signatures/{*file_path}",
            get(get_signature_status_handler),
        )
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));
    let files_router = Router::new().route("/files/{*file_path}", get(get_file_handler));
    let files_to_sign_router = Router::new()
        .route(
            "/files-to-sign/{*file_path}",
            get(get_files_to_sign_handler),
        )
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));
    let signers_router = Router::new().route("/get_signers/{*file_path}", get(get_signers_handler));
    let signers_chain_router = Router::new().route(
        "/get_artifact_signers_chain/{*artifact_path}",
        get(get_artifact_signers_chain_handler),
    );
    let artifact_info_router =
        Router::new().route("/get_artifact_info", post(get_artifact_info_handler));
    let revocation_router = Router::new().route("/get_revocation", post(get_revocation_handler));
    let revoke_router = Router::new().route("/revoke", post(revoke_handler)).layer(
        axum::middleware::from_fn_with_state(app_state.clone(), auth_middleware),
    );
    let assets_router = Router::new()
        .route("/assets", post(register_assets_handler))
        .layer(axum::middleware::from_fn_with_state(
            app_state.clone(),
            auth_middleware,
        ));
    let ping_router = Router::new().route("/ping", get(ping_handler));

    register_router
        .merge(update_signers_router)
        .merge(pending_router)
        .merge(signature_router)
        .merge(files_router)
        .merge(files_to_sign_router)
        .merge(signers_router)
        .merge(signers_chain_router)
        .merge(artifact_info_router)
        .merge(revocation_router)
        .merge(revoke_router)
        .merge(assets_router)
        .merge(ping_router)
}
