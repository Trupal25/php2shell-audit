# Lab pair

The compose file runs two disposable Apache/mod_php containers:

| Service | Image | Port | Purpose |
|---|---|---|---|
| `vulnerable` | `php:8.4.26-apache` | 8081 | Below the 8.4 gate |
| `patched` | `php:8.4.27-apache` | 8082 | At the 8.4 gate |

`index.php` is a harmless page. There is no exploit endpoint and no trigger in this
folder.

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
target; see `../../references/rce-validation.md`. The validator will reject the
template's placeholders and will not confirm RCE without a matching marker file.

Do not point the lab at production, and do not expose the lab ports outside the
isolated network.
