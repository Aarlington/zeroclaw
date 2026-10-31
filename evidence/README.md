# OIDC enrollment binding evidence

Source: [759ae4a5f1e4dffaa5d995503b222fc863e863d8](https://github.com/Aarlington/zeroclaw/commit/759ae4a5f1e4dffaa5d995503b222fc863e863d8).
Base: `1c1cd118ac536a1dd1bc79b9cce69cbdc04e4f29`. This bundle records a successful Ubuntu 24.04 / Rust 1.98.0
run of the exact four-file patch in `repair.patch`. It is supporting evidence, not an
upstream required-CI result or independent approval.

## Results

- OIDC suite: 32 passed. Strict gateway Clippy, format and whitespace passed.
- Removing only the browser-binding guard made the selected missing-cookie regression
  fail (200 instead of 400). Exact restoration followed; all 32 tests passed again.
- Native Chrome followed a mock IdP link back to the real enrollment callback. The
  same browser succeeded; a copied callback in another context was refused before
  exchange; replay was refused; two concurrent tabs both completed.
- Temporary fixture changes were restored and hash-verified; final suite: 32 passed.

See [machine receipt](receipt.json), [success page](browser-same-context.png), and
[refusal page](browser-other-context.png). The screenshots contain only synthetic data.
The browser receipt names the Chrome version and each observed result. Screenshots
show visible state; the request-count assertions establish whether exchange occurred.

## Reproduce

Use a disposable, clean checkout at the base above. Use Rust 1.98.0 with rustfmt and
Clippy, Node with its built-in WebSocket client, and Google Chrome on Ubuntu 24.04.
Keep these evidence files together outside that source checkout. Run:

```sh
RUSTUP_TOOLCHAIN=1.98.0 python3 run-validation.py /absolute/path/to/disposable-source
```

The script verifies the clean base, applies the patch, checks source hashes, runs the
tests and Clippy, performs the temporary negative control, and restores exact source
bytes. It then inserts the temporary native HTTP fixture, runs isolated Chrome contexts,
restores the source and repeats the suite. It does not need provider accounts or secrets.
It does not publish, approve or trigger CI. It compiles dependencies and can take time.

The first attempt used the wrong MIME type for the mock IdP page. Wiremock's
`set_body_string` forces plain text when the response is generated. This harness uses
`set_body_raw` with HTML, retains all browser assertions, and captures failure diagnostics.

## Limits

This is loopback HTTP with a mock IdP and the production enrollment routes, prefix and
security headers. It is not the full daemon, native TLS, dashboard popup integration,
real-provider acceptance, or release readiness. HTTPS cookie attributes have router
assertions in the source tests. The initial fixture error and local diagnostic probes
are not counted as a successful production browser run.
