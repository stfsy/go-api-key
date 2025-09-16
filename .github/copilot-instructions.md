# Copilot Instructions for go-api-key

## Go Lang Instruction
- Always wrap errors with %w
- Always handle errors

## Project Overview
- This Go module provides a secure, extensible API key generator and parser, supporting custom random ID generators and token hashers.
- Major components:
  - `APIKeyGenerator` (see `api_key.go`): main struct for generating, parsing, and validating API keys.
  - `RandomBytesGenerator` (see `random_bytes.go`): interface and default implementation for secure random string generation.
  - `Hasher` (see `token_hasher.go`, `argon2_hasher.go`): interface and implementations for hashing tokens (SHA256, Argon2id).

## Key Patterns & Conventions
- API keys are structured as: `<prefix><sep><short><sep><long>`, e.g., `mycorp#short#long`.
- Prefix: 1-8 chars, `[a-zA-Z0-9_-]`, must not contain the separator (default `#`).
- Separator is a `rune` (not string), default `#`, configurable via options.
- All errors are wrapped with `%w` for unwrapping.
- Custom generators/hashers can be injected via `ApiKeyGeneratorOptions`.
- All exported methods return detailed errors for invalid input or failures.

## Developer Workflows
- **Testing:** Run all tests (including fuzz) with `./test.sh` or `go test -fuzz=Fuzz`.
- **Linting:** Use `./lint.sh` (runs golangci-lint in Docker).
- **CI:** See `.github/workflows/tests.yml` for GitHub Actions test automation (runs `./test.sh`).
- **Fuzzing:** Fuzz tests are in `api_key_fuzz_test.go` and can be run with `go test -fuzz=Fuzz*`.

## Integration & Extensibility
- To add a new hashing or random generator strategy, implement the respective interface and inject via options.
- The default Argon2id parameters are set for strong security but can be tuned in `argon2_hasher.go`.
- The package is dependency-light, with only `github.com/stfsy/go-argon2id` as a direct dependency.

## Examples
- See `README.md` for usage patterns and API documentation.
- Example: 
  ```go
  gen, _ := apikey.NewApiKeyGenerator(apikey.ApiKeyGeneratorOptions{TokenPrefix: "mycorp"})
  key, _ := gen.GenerateAPIKey()
  ok, _ := gen.CheckAPIKey(key.Token, key.LongTokenHash)
  ```

## References
- Related/inspiration: [seamapi/prefixed-api-key](https://github.com/seamapi/prefixed-api-key/tree/main)

---
If you are an AI coding agent, follow these conventions and reference the files above for implementation details. When in doubt, prefer explicit error handling, strong typing, and extensibility.
