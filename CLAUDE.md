# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

coraza-envoy-extproc (`github.com/rikatz/coraza-envoy-extproc`) is a gRPC server implementing Envoy's **ext_proc** (External Processing) filter protocol. It uses [Coraza WAF](https://coraza.io/) to inspect and filter HTTP requests and responses flowing through Envoy Proxy.

**This is a PoC / experimental project.**

## Build & Run

```bash
make build                    # Build the binary
make image                    # Build the container image
make run                      # Full stack with docker compose (Envoy + WAF + upstream)
RULES_DIR=./my-rules make run # Use custom rules directory
```

## Architecture

The codebase is intentionally small — two Go files:

- **cmd/coraza-envoy-extproc/main.go** — CLI entrypoint. Parses flags, initializes Coraza WAF from a directives file, starts the gRPC server.
- **pkg/waf/waf_extproc.go** — Core logic. Implements `ExternalProcessorServer` (Envoy ext_proc gRPC interface). Handles the bidirectional stream lifecycle:
  1. `RequestHeaders` → creates a Coraza transaction (keyed by `x-request-id`), processes connection info + headers
  2. `RequestBody` → accumulates and evaluates request body against WAF rules
  3. `ResponseHeaders` → evaluates response headers (e.g., DLP-style header leak detection)
  4. `ResponseBody` → accumulates and evaluates response body (e.g., DLP-style content inspection)

On rule match, the server sends an `ImmediateResponse` (403) for request-phase blocks, or clears the body and closes the connection for response-phase blocks.

## Key Protocols & Dependencies

- **Envoy ext_proc**: `envoy.service.ext_proc.v3.ExternalProcessor` — the gRPC streaming interface. Envoy config is in `config/envoy/envoyextproc.yaml`.
- **Coraza WAF**: `github.com/corazawaf/coraza/v3` — WAF engine. Rules use ModSecurity SecRule syntax (see `config/rules/`).
- **go-control-plane**: `github.com/envoyproxy/go-control-plane/envoy` — Envoy protobuf types.

## Config Structure

- `config/envoy/` — Envoy proxy configuration
- `config/rules/` — Coraza WAF rules (ModSecurity SecRule format). The entire directory is mounted into the container at `/rules`, so rules can `Include` other files. Override with `RULES_DIR` env var in docker compose.

Phases map to ext_proc stream stages (phase 1 = request headers, phase 2 = request body, phase 3 = response headers, phase 4 = response body).
