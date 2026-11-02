# Evidence and integrity

## Success criterion

Success required all of the following from the real challenge:

1. a D response containing the exact per-run marker;
2. `/flag` immediately after that marker;
3. the response-local canonical `X-Attempt-ID`;
4. exactly one official verifier request; and
5. verifier HTTP 200 with `verified:true`.

Crashes, disconnects, HTTP 200, OOM gates, laboratory flags, and markers without verifier acceptance were not treated as a solve.

## Accepted private evidence

The complete evidence remains local on the lab at:

```text
/root/bridge/stock/evidence/verifier-accepted-20261102/
```

It contains the original controller, acquisition receipts, terminal receipt, winning D response, verifier response, and live flag. This repository intentionally does not copy the sensitive response entities or flag.

Sanitized integrity handles:

| Artifact | SHA-256 |
|---|---|
| accepted controller | `17d1cf9dde5b85adbd294d8df3a27b3f850567b9cbbe3bf3e77734d95cdab027` |
| heap receipt | `6645a976074d804c4a7ea9f838a6ab2ee582e1f3b9e6264461f265d28e3c2608` |
| code receipt | `772d4265034d0f3deacb979264096084ba8352d6d2ce9d5e6262f4822ae1deb3` |
| terminal receipt | `6f294bcd67838fd2bbaa3cd9eb32f63b1be66ab3610ed15c04f0f59807b65aa6` |
| winning D response | `b3d792a0ec69ceedfb4ef52ee7ab6496f3a359a48319f3942f43e540fa897085` |
| verifier response | `4615ba5cb66c45c62770d51f0beda28978acf0c4eb2ff74aa5d1b433ee5ec0a7` |

The flag hash and attempt ID are intentionally omitted.

## Accepted source identities

| Entry point | SHA-256 |
|---|---|
| cookie-free heap oracle | `6cacbf19e29dced74687a7c5465f0b75bbca11247d52b73cbe2312b4cd185817` |
| strict code-pointer oracle | `6f93a2a02116e5690a6e30720f9b0c7cf5cc54a5ab8d9b14fc65ccd3190d13b3` |
| accepted terminal controller | `17d1cf9dde5b85adbd294d8df3a27b3f850567b9cbbe3bf3e77734d95cdab027` |

`evidence/controller.accepted.py` preserves the exact terminal source. The packaged runnable controller differs only in two corrected descriptive strings.

## Excluded material

- live flag and its hash;
- accepted `X-Attempt-ID`;
- raw request or response bodies;
- cookies and session captures;
- verifier response entity;
- historical campaign receipts and logs;
- internal host topology and unrelated work products.

## Proof labels

| Claim | Status |
|---|---|
| WAF bypass reaches PHP | Proven live |
| Heap oracle returns a canonical base | Proven live |
| libphp oracle returns a canonical base | Proven live |
| Terminal geometry executes on the exact replica | Proven |
| Live terminal returns `/flag` | Proven live |
| Flag and attempt ID are response-local | Proven live |
| Official verifier accepts the result | Proven live |
| Stable cookie determines Cloudflare affinity | Unverified |
| Twenty-five lanes guarantee execution | False |
