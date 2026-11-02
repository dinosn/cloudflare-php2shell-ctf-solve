# What changed between repeated failure and delivery

The final result did not come from discovering a new PHP primitive. The WAF bypass and terminal geometry already worked. The process changed so that a valid dynamic address pair and enough terminal locality opportunities were present at the same time.

## 1. The replica stopped lying about ASLR

A host script had repeatedly forced `kernel.randomize_va_space=0`. Fixed bases made restart behavior look more deterministic than the real challenge.

After restoring ASLR to `2`, the unchanged payload succeeded across independently randomized one-worker replicas, the direct fixed-eight origin, and the exact fresh-connection WAF front. This proved that the payload offsets and WAF bypass survived real ASLR. It did not directly cause the remote flag.

## 2. Environment identity became a gate

Earlier work mixed source-built, Bookworm, Trixie, and official-Docker observations. The final process treated the official PHP 8.5.11 Apache image and its measured module profile as the relevant class. Results from another distribution/build were no longer allowed to override exact-target evidence.

## 3. Acquisition remained cookie-free

A stable `PHPSESSID` during acquisition changes which session ID PHP selects and reproducibly kills the B leak. The accepted sequence therefore used:

- no cookie for heap acquisition;
- no cookie for libphp acquisition;
- one stable synthetic session only for terminal A/B/S/D.

The stable-session terminal had already been validated on the exact replica. Stable session alone was not enough: the 8-lane stable-session controller still missed live.

## 4. Both bases were measured, not inferred

Historical runs guessed libphp from a heap delta. Live epochs demonstrated different separations. The accepted process instead required:

- a fresh canonical heap supported by strict votes;
- an immediate independent code-pointer leak;
- a canonical 2 MiB-aligned libphp base;
- agreeing votes and `epoch_risk=false`.

The observed separation was used as a plausibility check for that epoch, never as a build constant.

## 5. Code-oracle fanout was reduced

The accepted code acquisition used fanout 5 rather than a larger churn-heavy wave. This produced a strict module base with less reset/disconnect pressure. It was operationally useful, although no controlled experiment proves that fanout reduction itself caused terminal execution.

## 6. Terminal locality coverage widened from 8 to 25

This was the only executable difference between the failed stable-session controller and the accepted controller:

```diff
-TERMINAL_COUNT = 8
+TERMINAL_COUNT = 25
```

Unchanged elements included:

- WAF preamble and framing;
- all four multipart bodies;
- block `0x59400`;
- official-Docker profile and gadget offsets;
- `derived-adjacent` ROP mode;
- S and D pressure;
- stable-session sender;
- rolling S-completion → immediate-D schedule;
- verifier logic.

The 8-lane run made 121 exploit POSTs and returned no marker/flag. The accepted 25-lane run made 155 exploit POSTs and returned 11 qualifying marker/flag responses.

A later refresh supplied a useful control: the first 25-lane terminal missed, and an immediate second terminal using the same still-valid pair succeeded. Therefore 25 lanes improve the probability of compatible backend/PHP-worker placement; they do not make it deterministic.

## 7. Verification became part of exploitation

The earlier workflow could retrieve a valid flag and then lose it to sandbox reset before manual form submission. The accepted controller binds flag and `X-Attempt-ID` from one D response and submits them immediately. Success is defined only by the official verifier's `verified:true` response.

## Proven facts versus interpretation

### Proven

- The 8-lane and 25-lane controllers differ by one executable constant.
- The 8-lane live run missed.
- The first accepted 25-lane run produced 11 flag-bearing responses.
- A later 25-lane wave missed and its immediate same-pair repeat succeeded.
- Cookie-bearing acquisition breaks the leak; cookie-free acquisition succeeds.
- Stable session is compatible with the terminal but insufficient at eight lanes.

### Best-supported interpretation

Wider rolling coverage increased the number of opportunities for seed and fire requests to reach a compatible backend/container/PHP-worker state.

### Not proven

- That `PHPSESSID` controls Cloudflare routing.
- That a particular D landed on a worker specifically because of the cookie.
- That 25 lanes always succeed.
