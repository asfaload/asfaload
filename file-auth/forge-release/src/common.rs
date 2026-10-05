pub trait ReleaseInfo: std::fmt::Debug + Send + Sync {
    fn origin_prefix(&self) -> &str;
    fn owner(&self) -> &str;
    fn repo(&self) -> &str;
    fn tag(&self) -> &str;
}
