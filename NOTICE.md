# Attribution and provenance

This repository packages a local composition and calibration used for an authorized CTF. It does not replace the copyright or licensing terms of the original researchers and repositories.

Directly credited lineages retained in the source:

- **9bie**, `php2shell-bypass-aslr-exp`, commit `17e98ee81025cccfd94b4f9c9a17bf269c65ff75`: cross-request session-state OOM and forged-cookie disclosure geometry.
- **Cookiengineer**, `actual-php2shell`, commit `1d5208ba5090cbbc56a091f6607996c3bbb21171`: incomplete-bucket/object-destruction RCE sink.
- **KillaBoi**, `KillaBoi/StealMyBitcoin-PoC`: nested multipart amplification and session-cookie disclosure class, reimplemented in the local p2s support package.
- **dinosn**, `php-cve-2026-10961x-lab-poc`, commit `b1e419912219691417c72b122f6eb410b938eee7`: instrumentation, porting, stock-configuration experiments, profiles, and worker-delivery research.

Additional reviewed public PoCs are credited in `src/stock/php8511_rce.py`, including Eness, 0x4148, Ikow, Murrez, and Syrex1013 with their recorded revisions.

The Cloudflare challenge, PHP, and all third-party project names and trademarks belong to their respective owners.
