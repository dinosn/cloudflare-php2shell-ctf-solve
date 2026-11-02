# Safety and scope

This repository is a private archive of an explicitly authorized public CTF solve. It contains working memory-corruption exploit tooling.

Rules for use:

- Run only against the named CTF while it remains authorized, or against systems you own and control.
- Do not reuse historical heap/libphp addresses after a sandbox reset.
- Do not remove the explicit `--authorized-live` gate for remote execution.
- Keep generated output under an untracked `runs/`, `out/`, or temporary directory.
- Never commit flags, raw responses, cookies, attempt IDs, authorization headers, or verifier entities.
- Revalidate the exact PHP binary, configuration, SAPI, front-end behavior, and ASLR state before treating any result as transferable.
- Treat a crash, OOM, HTTP success, or marker as partial evidence. Only the challenge verifier established the completed solve.

The included offline verification script sends no network requests.
