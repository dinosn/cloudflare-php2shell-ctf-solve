# Technical solve

## Verdict

**Proven live:** the chain bypassed the challenge WAF, acquired fresh heap and module bases, executed the terminal against the real PHP sandbox, returned `/flag`, bound it to the same response's `X-Attempt-ID`, and received `verified:true` from the official verifier.

## Challenge model

The target was the Cloudflare PHP2Shell CTF endpoint backed by the official PHP 8.5.11 Apache class. Relevant measured properties were:

- PHP 8.5.11 with a 128 MiB memory limit;
- `post_max_size=8M`;
- multipart upload-progress parsing enabled;
- a Cloudflare WAF/proxy in front of a multiworker backend;
- request-to-backend/PHP-worker placement not controlled by a client TCP connection.

The WAF bypass was already solved before terminal delivery. An inert multipart preamble places the exploit-critical `PHP_SESSION_UPLOAD_PROGRESS` material beyond the measured inspection window while PHP continues parsing the complete body.

## Chain architecture

### Heap oracle

`src/stock/flood_heap_oracle_live.py` runs a cookie-free A/B wave. A successful fatal allocation exposes a triple-length value from which the aligned Zend heap candidate is decoded. The accepted run selected a canonical heap base from four strict votes.

The repository contains the exact accepted lab source. A later Mac file with the same name had drifted to a stable-cookie variant and was intentionally not used here.

### libphp oracle

`src/native/code_dtor_fatal_probe.py` uses the field-66 fatal-channel shape. The fatal size encodes the `zval_ptr_dtor` pointer, and the official PHP 8.5.11 profile derives a 2 MiB-aligned libphp base.

The accepted run used fanout 5, produced two agreeing strict votes, and reported `epoch_risk=false`. The heap-to-libphp separation observed in that epoch was evidence, not a reusable constant.

### Terminal

`src/stock/rolling_seedfire_stable25_live.py` builds four request types:

- **A — arm:** creates the stale upload-progress/session condition.
- **B — retained history:** establishes the reclaim history expected by the terminal.
- **S — seed:** places the forged object and terminal chain.
- **D — destroy/fire:** reclaims and walks the prepared state, writing the run marker and `/flag` into the HTTP response when placement aligns.

Accepted geometry:

```text
block              = 0x59400
profile            = official-docker
terminal mode      = derived-adjacent
A requests         = 80
B requests         = 25
S requests         = 25
D requests         = up to 25
S headers          = 600000
D headers          = 402500
maximum exploit POSTs = 155
```

The terminal uses two 25-worker executors. Every S begins concurrently. When an individual S returns HTTP 200 and the expected OOM-4096 value, its corresponding D is submitted immediately while other S requests may still be in flight.

The same synthetic `PHPSESSID` is carried on terminal A/B/S/D. Each request still opens its own TLS connection; the cookie is session identity, not proof of one persistent connection or Cloudflare load-balancer affinity.

## Verifier binding

A crash, HTTP 200, marker, flag-like string, or lab proof is insufficient. A D response qualifies only when it contains:

1. the exact random marker generated for this terminal run;
2. a canonical UUID or braced flag immediately following the marker; and
3. a canonical UUID-format `X-Attempt-ID` in the same raw response.

The first qualifying D response may trigger one verifier request. The final success gate is verifier HTTP 200 with JSON `verified` equal to `true`. Only then does the controller persist `flag.txt` and set `VERIFIER_ACCEPTED`.

This eliminated the manual-submission race in which the sandbox reset invalidated an earlier flag/attempt pair.

## Accepted run

Historical values, retained only to document the proof:

```text
heap              = 0x7f7261c00000
libphp            = 0x7f7263800000
observed separation = +0x1c00000
```

Terminal receipt:

```text
A: 80/80 HTTP 200, OOM-4096
B: 25/25 HTTP 200, OOM-4096
S: 25/25 HTTP 200, OOM-4096
D: 22 HTTP 200, 3 HTTP 500
marker/flag responses: 11
winning lane: D23
verifier: HTTP 200, verified=true
verdict: VERIFIER_ACCEPTED
```

Those addresses are stale after sandbox reset and must not be reused.

## Source fidelity

`evidence/controller.accepted.py` is the byte-identical controller used for the accepted run. The runnable copy corrects two stale descriptive strings (`eight` and `S8`) to `25` and `S25`; executable behavior is unchanged.
