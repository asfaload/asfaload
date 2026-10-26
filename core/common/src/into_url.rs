use std::fmt::Display;

use url::Url;

// Trait to make it easier to accept both string and url types in our functions.
pub trait IntoUrl: Display + Send {
    fn into_url(self) -> Result<Url, url::ParseError>;
}

impl IntoUrl for Url {
    fn into_url(self) -> Result<Url, url::ParseError> {
        Ok(self)
    }
}

impl IntoUrl for &Url {
    fn into_url(self) -> Result<Url, url::ParseError> {
        Ok(self.clone())
    }
}

impl IntoUrl for &str {
    fn into_url(self) -> Result<Url, url::ParseError> {
        Url::parse(self)
    }
}

impl IntoUrl for String {
    fn into_url(self) -> Result<Url, url::ParseError> {
        Url::parse(&self)
    }
}
impl IntoUrl for &String {
    fn into_url(self) -> Result<Url, url::ParseError> {
        Url::parse(self)
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    /// This helper stands for the target use of the trait: one function that
    /// accepts an url given as a `Url`, a `&str`, or a `String`.
    fn parse_with_into_url<T: IntoUrl>(input: T) -> Result<Url, url::ParseError> {
        input.into_url()
    }

    /// This helper checks that the `Display` bound of the trait is usable in a
    /// generic function.
    fn label_with_into_url<T: IntoUrl>(input: &T) -> String {
        format!("{input}")
    }

    #[test]
    fn test_url_into_url_keeps_the_same_url() -> anyhow::Result<()> {
        let url = Url::parse("https://github.com/acme/tool")?;
        let result = url.clone().into_url()?;
        assert_eq!(result, url);
        Ok(())
    }

    #[test]
    fn test_str_into_url_parses_the_url() -> anyhow::Result<()> {
        let result = "https://github.com/acme/tool".into_url()?;
        assert_eq!(result.as_str(), "https://github.com/acme/tool");
        Ok(())
    }

    #[test]
    fn test_string_into_url_parses_the_url() -> anyhow::Result<()> {
        let result = String::from("https://github.com/acme/tool").into_url()?;
        assert_eq!(result.as_str(), "https://github.com/acme/tool");
        Ok(())
    }

    #[test]
    fn test_generic_function_accepts_url_str_and_string() -> anyhow::Result<()> {
        let from_url = parse_with_into_url(Url::parse("https://example.com/a")?)?;
        let from_str = parse_with_into_url("https://example.com/b")?;
        let from_string = parse_with_into_url(String::from("https://example.com/c"))?;

        assert_eq!(from_url.as_str(), "https://example.com/a");
        assert_eq!(from_str.as_str(), "https://example.com/b");
        assert_eq!(from_string.as_str(), "https://example.com/c");
        Ok(())
    }

    #[test]
    fn test_display_bound_is_available_on_into_url_values() -> anyhow::Result<()> {
        let url = Url::parse("https://example.com/x")?;

        assert_eq!(label_with_into_url(&url), "https://example.com/x");
        assert_eq!(
            label_with_into_url(&"https://example.com/y"),
            "https://example.com/y"
        );
        assert_eq!(
            label_with_into_url(&String::from("https://example.com/z")),
            "https://example.com/z"
        );
        Ok(())
    }

    #[test]
    fn test_invalid_str_into_url_reports_parse_error() {
        match "not a url".into_url() {
            Err(url::ParseError::RelativeUrlWithoutBase) => {}
            Err(e) => panic!("Expected RelativeUrlWithoutBase error, got: {e}"),
            Ok(u) => panic!("Expected RelativeUrlWithoutBase error, got Ok({u})"),
        }
    }

    #[test]
    fn test_invalid_string_into_url_reports_parse_error() {
        match String::from("not a url").into_url() {
            Err(url::ParseError::RelativeUrlWithoutBase) => {}
            Err(e) => panic!("Expected RelativeUrlWithoutBase error, got: {e}"),
            Ok(u) => panic!("Expected RelativeUrlWithoutBase error, got Ok({u})"),
        }
    }
}
