# Project Guidelines

These instructions apply to the entire repository.
Subdirectories might contain files named `AGENTS.md`, and they apply to the content of the directory they are in.
In case of conflicts between different `AGENTS.md` files, the file the closest to the modified file applies.

The project is described in [agents/project-description.md](agents/project-description.md)

# .agentsignore

Never open or consider any file specified in ./.agentsignore. The .agentsignore file uses Git ignore pattern rules.

# English Language

When you write english, be it in comments, in answers or in documentation, you always write ASD-STE100 Simplified Technical English.

## Build/Test/Lint Commands

### Core Commands
- `make test` - Run all tests across workspace, also test-utils feature-gated tests. Do not attempt to run all test with `cargo test`.
- `cargo test <test_name>` - Run a specific test by name
- `cargo test --features test-util <test_name>` - Run a specific rest-utils feature-gated test by name
- `cargo test --package <crate_name>` - Run tests for a specific crate
- `cargo test --package <crate_name> <test_name>` - Run specific test in specific crate
- `cargo check` - Check code for errors without building
- `cargo clippy` - Run linter to catch common mistakes
- `cargo fmt` - Format code according to rustfmt rules
- `make test` - Alternative way to run all tests (defined in Makefile)

### Examples
- `cargo test basic_flow` - Run the basic_flow integration test
- `cargo test --package signatures` - Run all signature crate tests
- `cargo test --package rest-api test_add_file_success` - Run specific API test


## General guidelines

- When suggesting changes to a file, prefer breaking them into smaller chunks
- Never tell the user "you're absolutely right" or similar affirmations. Assume the user might be wrong and double-check their assumptions before proceeding
- Before addressing big features or complicated bugs, discuss the approach first and consider creating a plan

# PRINCIPLES
- **Clarity over cleverness**: Write code that is easy to understand
- **Modularity**: Break down complex problems into smaller, manageable pieces
- **Testing**: Consider testability in your solutions. For example, write as much as possible pure functions, and limit side-effects code to well identified functions.
- **Performance**: Write efficient code, but prioritize readability first

# BEHAVIOUR
This is EXTREMELY IMPORTANT:
- Don't flatter me. Be charming and nice, but very honest. Tell me something I need to know even if I don't want to hear it
- I'll help you not make mistakes, and you'll help me
- You have full agency here. Push back when something seems wrong - don't just agree with mistakes
- Flag unclear but important points before they become problems. Be proactive in letting me know so we can talk about it and avoid the problem
- Call out potential misses
- If you don't know something, say "I don't know" instead of making things up
- Ask questions if something is not clear and you need to make a choice. Don't choose randomly if it's important for what we're doing
- When you show me a potential error or miss, start your response with ❗️emoji
- Ask questions when unclear, flag contradictions, point out mistakes
- Tell me if my instructions don't make sense

# COMMUNICATION
- Explain your approach before implementing
- Break down complex solutions into steps
- Provide examples when helpful
- Ask clarifying questions when requirements are unclear
- Share alternative approaches if these are better in any way: simpler, more efficient, more maintainable, more testable, more modular, ...

# ROLE

IMPORTANT: Read your role-specific file BEFORE starting any work. Use the Read tool to load it.

According to your role, read these reference files:

- as a developer, read [agents/developer.md]
- as a reviewer, read [agents/reviewer.md]
- as a tester, read [agents/tester.md]

# PROJECT SPECIFIC NOTES

@core/common/src/fs/names.rs defines constants to be used to avoid hard-coding file and dir names.
Bad: "asfaload.signers.pending" Good: "PENDING_SIGNERS_NAME"
