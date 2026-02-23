# Contributing

See also [AGENTS.md](./AGENTS.md) for codebase conventions.

## Running Tests

### Test Structure

Tests are organized into three directories under `crates/vault-client-rs/tests/`:

 * `tests/unit/`: unit tests with no external dependencies
 * `tests/mock/`: mock tests using wiremock — no Vault needed
 * `tests/integration/`: integration tests that require a running Vault node

### Prerequisites

Install [cargo-nextest](https://nexte.st/):

```bash
cargo install cargo-nextest
```

### Run Unit and Mock Tests (No Vault Needed)

```bash
cargo nextest run --all-features -E 'binary(unit) or binary(mock)'
```

### Run Integration Tests

Integration tests require a running Vault dev server. Start one:

```bash
docker run --rm --cap-add=IPC_LOCK \
  -e 'VAULT_DEV_ROOT_TOKEN_ID=myroot' \
  -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' \
  -p 8200:8200 \
  --name dev-vault \
  hashicorp/vault
```

Or with Nu shell:

```nu
(docker run --rm --cap-add=IPC_LOCK
  -e VAULT_DEV_ROOT_TOKEN_ID=myroot
  -e VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200
  -p 8200:8200
  --name dev-vault
  hashicorp/vault)
```

Then run with the required env vars:

```bash
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=myroot \
  cargo nextest run --all-features -E 'binary(integration)'
```

Here's a Nu shell equivalent:

```nu
with-env { VAULT_ADDR: "http://127.0.0.1:8200", VAULT_TOKEN: myroot } {
  cargo nextest run --all-features -E 'binary(integration)'
}
```

Integration tests run sequentially (configured in `.config/nextest.toml`).

### Run All Tests

```bash
VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=myroot \
  cargo nextest run --all-features
```

Or in Nu shell:

```nu
with-env { VAULT_ADDR: "http://127.0.0.1:8200", VAULT_TOKEN: myroot } {
  cargo nextest run --all-features
}
```

### Run Property-Based Tests

```bash
cargo nextest run --all-features -E 'test(~prop_)'
```

### Run a Specific Test

```bash
cargo nextest run --all-features -E 'test(=test_name_here)'
```

### nextest Filter Predicates

 * `test(pattern)`: substring match on test name
 * `binary(pattern)`: match test binary name (unit, mock, integration)
 * `test(=exact)`: exact test name match
 * `test(/regex/)`: regex match
