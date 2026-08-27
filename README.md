# vuln-app-list

Public deploy target for intentional vulnerability labs used to test scanners.

Apps in this repository are **deliberately vulnerable**. Do not use them for real data or production workloads.

Labs are generated from a private template repo and published here for [Render](https://render.com) Blueprint deploys (`render.yaml`).

## Labs

See `catalog.json` for the machine-readable list. Each lab exposes:

- `GET /health`
- `GET /.well-known/lab-manifest.json`
- Vulnerable routes documented in the lab manifest

## Deploy

1. Connect this repo to Render as a **Blueprint** (path: `render.yaml`).
2. Deploy on the free plan (no custom domain required).
3. Point your scanner at the `*.onrender.com` service URL from `catalog.json`.
