# ThreatCheck: Upload & Scan — GitHub Action

Uploads a build artifact to ThreatCheck and triggers a binary composition scan.
Implements exactly the flow in *ThreatCheck Jenkins Plugin — Build Specification v1.0
(21 September 2026)* — same spec as the Jenkins plugin, same 3-step flow, same behavior.

1. **Presign** — `POST {base-url}/v1/products/{productId}/firmware` reserves a destination
   and creates the release/scan records.
2. **Upload** — the artifact is sent straight to Azure Blob Storage in 8 MiB blocks, using
   fixed-width block ids, then committed with a `comp=blocklist` PUT. This traffic never
   touches the ThreatCheck API or the API token.
3. **Complete** — `POST {base-url}/v1/products/{productId}/versions/{productVersionId}/uploaded`
   confirms the upload and starts the scan.

The action exits as soon as step 3 returns `"status": "hashing"`. It never polls for results
and never fails the workflow on scan findings — that is explicitly out of scope.

## Usage

```yaml
name: CI

on: [push]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Build
        run: ./build.sh   # your existing build stage, produces the artifact

      - name: ThreatCheck upload & scan
        uses: your-org/threatcheck-github-action@v1
        with:
          base-url: https://your-org.threatcheck.io
          api-token: ${{ secrets.THREATCHECK_API_TOKEN }}
          product-id: prd_01J9ZQK3QW8YB2VN4T6H5M0XD1
          artifact-path: build/firmware.bin
          # version: left unset -> defaults to the GitHub run number
```

## Inputs

| Input | Required | Default | Notes |
|---|---|---|---|
| `base-url` | yes | — | ThreatCheck gateway URL. **No default** — the public base path isn't settled yet (see below) |
| `api-token` | yes | — | ThreatCheck API token with the `scanning:sbom:manage` scope — pass via `secrets.*`, never inline |
| `product-id` | yes | — | `prd_…`, created manually in the portal |
| `artifact-path` | yes | — | Path to the built artifact, relative to the workspace |
| `version` | no | GitHub run number | Release label — your build/tag identifier |
| `content-type` | no | `application/octet-stream` | Must match the artifact's actual type — a mismatch is rejected after the full upload completes |

## Outputs

| Output | Description |
|---|---|
| `product-scan-id` | The scan that was queued |
| `product-version-id` | The release/version id the artifact was attached to |
| `upload-id` | Safe to log — identifies the upload without granting access to it |
| `status` | Upload status from the complete step, e.g. `hashing` |

## The open blocker: `base-url`

Per spec §9, the public base path for the deployed environment isn't settled yet (a
gateway-prefix vs. API-prefix decision that sits with the platform team). This action
deliberately ships with **no default** for `base-url` so nothing silently points at a broken
path. You can fully test this action today against a local ThreatCheck stack; when the
decision lands, only the `base-url` value consumers use changes — no action code changes.

## Things this action deliberately does NOT do

- Poll for scan status or results
- Fail/gate the workflow based on findings
- Fetch an SBOM back
- Create products (products are created by a person in the portal)
- Attach to an existing release ("Form B" from the spec) — only "Form A" (create a new
  release) is implemented, matching the Jenkins plugin

## Security notes carried over from the spec

- The API token is sent as `Authorization: Bearer <token>` on every ThreatCheck call, and
  **never** attached to the Azure blob-storage requests in step 2.
- `uploadUrl` (the SAS-bearing URL from presign) is treated as a credential and is never
  printed to workflow logs or written to outputs — only the opaque `upload-id` is exposed.
- 401/403/404/400 fail immediately with the server's own message; 429/503 retry with backoff;
  409 is reported as "already in progress" rather than a generic error.

## Project layout

| File | Purpose |
|---|---|
| `action.yml` | Action metadata — inputs, outputs, and the composite step |
| `scripts/upload-and-scan.js` | The full 3-step flow: presign → block upload → complete, using Node's built-in `fetch` (no npm dependencies) |

## Local testing

This repo includes a spec-compliant mock server (`mock-threatcheck-server/`) that simulates
the real 3-step flow, including proper Azure-style block upload — so the action's block-upload
logic is genuinely exercised, not just a simplified stand-in.

```bash
# terminal 1
cd mock-threatcheck-server
node server.js

# terminal 2
THREATCHECK_BASE_URL="http://localhost:4000" \
THREATCHECK_API_TOKEN="test-token" \
THREATCHECK_PRODUCT_ID="prd_test123" \
THREATCHECK_ARTIFACT_PATH="./some-test-file.bin" \
GITHUB_OUTPUT="/tmp/github_output.txt" \
node scripts/upload-and-scan.js
```
