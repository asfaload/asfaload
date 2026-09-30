mod error;
pub mod fileserver;
mod forge_info;
pub mod forges;
pub mod github;
pub mod gitlab;
mod origin;
mod traits;
pub mod url_info;

pub use error::ForgeUrlError;
pub use forge_info::ForgeInfo;
pub use forges::{Forges, get_forge};
pub use origin::path_prefix_from_url;
pub use traits::{ForgeTrait, ForgesPathMethods};
