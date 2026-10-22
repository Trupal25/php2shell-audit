# Lab pair

The compose file runs two disposable Apache/mod_php containers:

| Service | Image | Port | Purpose |
|---|---|---|---|
| `vulnerable` | `php:8.4.26-apache` | 8081 | Below the 8.4 gate |
| `patched` | `php:8.4.27-apache` | 8082 | At the 8.4 gate |

`index.php` is a harmless page. There is no exploit endpoint and no code-execution
trigger in this folder. `repro.php` only reports what the parser retained; the
bounded OOM probe is in `scripts/lab-repro.sh`.

## Use it to validate the audit, not to exploit

```bash
cd assets/lab
docker compose up -d
cd ../..

# The vulnerable pair should be P0; the patched pair should be PATCHED.
bash scripts/assess-url.sh --url http://127.0.0.1:8081/
bash scripts/assess-url.sh --url http://127.0.0.1:8082/

# Full pipeline, with a report.
bash scripts/run-audit.sh --url http://127.0.0.1:8081/ \
  --asset lab-vulnerable --out audit-lab-vulnerable

docker compose -f assets/lab/docker-compose.yml down
```

Private/loopback targets need no `scope.txt`.

## RCE evidence

`rce-evidence.example.json` is a shape-only template. To exercise the RCE stage, an
authorized validation module must produce a real artifact and marker for an isolated
target; see `../../references/rce-validation.md`. The opt-in RCE adapter has its own
calibrated profile (`rce.ini`, `apache-single.conf`) and is documented in
`../../modules/rce-modphp/README.md`; this default pair remains a harmless
version/OOM lab and contains no exploit endpoint. The validator will reject the
template's placeholders and will not confirm RCE without a matching marker file.

## Real request-parsing reproduction (separate from RCE)

`repro.ini` and `repro.php` support the bounded OOM differential run by
`scripts/lab-repro.sh`. It sends one multipart request with the session
upload-progress preamble and 150,000 ignored part headers to both images:

```bash
cd ../..
bash scripts/lab-repro.sh --out repro-lab --json
```

The vulnerable image is expected to hit `Allowed memory size ... exhausted`; the
patched image is expected to return the normal JSON probe response. This is a
request-parsing behavior difference, **not** RCE. The artifact always has empty
`execution_effects` and is reported through `repro_state`, never `rce_state`.
See `references/lab-reproduction.md`.

The Docker-gated integration test runs the reproduction independently and then
feeds its artifact through `run-audit.sh`:

```bash
bash scripts/lab-integration.sh --out lab-integration-1
```

Do not point the lab at production, and do not expose the lab ports outside the
isolated network.
