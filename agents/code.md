# CODE STYLE
- Use consistent naming conventions
- Use descriptive variable and function names (avoid abbreviations except very common ones)
- Follow language-specific style guides
- Keep functions small and focused
- Use meaningful variable and function names
- Add comments for complex logic, but again, explain the why, not the what.
- Code comments must not reference plan documents, plan tasks or steps,
  review notes, todo files or other process artifacts: a reader of the code
  has none of those documents. Comments explain what the code does; such
  references belong in commit messages and todo files instead.

# BEST PRACTICES
- **DRY (Don't Repeat Yourself)**: Avoid code duplication. Extract repeated code to functions.
- Prefer a functional approach to an object oriented approach. For example: if possible and reasonable, use iterators and avoid for loops.
- **Error Handling**: Always handle potential errors gracefully.
- **Security**: Consider security implications in your code
- **Version Control**: Write clear commit messages

Read [producing_better_code.md](./producing_better_code.md) which collects lessons from earlier code development in this project.

## Code Style Guidelines

### Project Structure
- **Core crates**: Located in `core/` directory, provide foundational features
- **features_lib**: Central crate exposing all core features. Code outside `core/` should only depend on `features_lib`
- **client-cli**: Command-line tool for client operations
- **rest-api**: Server component with actor-based architecture for git operations

### Imports and Dependencies
- Use `use` statements at the top of files, organized by standard library, external crates, then local modules
- External crate imports should be grouped alphabetically
- Local module imports should be grouped by relationship (e.g., all `common::*` together)
- Prefer explicit imports over glob imports except for test modules and prelude patterns

### Naming Conventions
- NEVER hardcode a value if it is also available as constant
- **Types**: `PascalCase` (e.g., `AsfaloadKeyPair`, `SignedFileWithKind`)
- **Functions/Methods**: `snake_case` (e.g., `sha512_for_content`, `add_signature`)
- **Constants**: `SCREAMING_SNAKE_CASE` (e.g., `SIGNERS_DIR`, `PENDING_SIGNERS_DIR`)
- **Traits**: Often include descriptive context (e.g., `AsfaloadKeyPairTrait`, `AsfaloadSignatureTrait`)
- **Enum variants**: `PascalCase` (e.g., `FileType::Artifact`, `KeyFormat::Asfaload`)

### Error Handling
- Use `Result<T, ErrorType>` pattern for functions that can fail
- Define specific error types in each domain (e.g., `KeyError`, `SignError`, `VerifyError`)
- Use `thiserror` for custom error types with proper error messages
- Use `anyhow::Result` for test functions and complex error chains
- Never use `.unwrap()` in production code - only in tests

### Types and Patterns
- Use marker types for compile-time safety (e.g., `InitialSignersFileMarker`, `ArtifactMarker`)
- Implement traits for common behavior patterns (e.g., `AsfaloadPublicKeyTrait`)
- Use `PhantomData<T>` for marker type parameters
- Prefer `Option<T>` over nullable patterns
- Use `enum` for state machines and variant types

### Testing Patterns
- Unit tests in `#[cfg(test)]` modules within source files
- Integration tests in `tests/` directories
- Use `tempfile::TempDir` for test isolation
- Use `anyhow::Result<()>` as test function return type
- Test both success and error cases
- Use descriptive test names that explain the scenario
- Structure tests with arrange-act-assert pattern
- do not write this:
```
        assert!(result.is_err());
        match result.unwrap_err() {
            ApiError::InvalidRequestBody(msg) => {
                assert!(msg.contains("null bytes"));
            }
            _ => panic!("Expected InvalidRequestBody error"),
        }

```
but
```
        match result{

            Err(ApiError::InvalidRequestBody(msg)) => {
                assert!(msg.contains("null bytes"));
            }
            Err(e) => {
                panic!("Expected ApiError::InvalidRequestBody but got {}", e)
            },
            Ok(_) => panic!("Expected InvalidRequestBody error, go ok value !",),
        }
```
as this will report the unexpected error we got

### Async Code
- Use `#[tokio::main]` for async main functions
- Use `#[tokio::test]` for async test functions
- Handle async results with `?` operator properly
- Use proper error types for async operations

### Security
- Never expose private keys in logs or error messages
- Use proper password handling for encrypted keys
- Validate all external inputs
- Use constant-time comparisons for sensitive data

### Code checks
These checks must pass without errors or warnings:
- `cargo check` - Check code for errors without building
- `cargo clippy` - Run linter to catch common mistakes
- `cargo fmt` - Format code according to rustfmt rules
