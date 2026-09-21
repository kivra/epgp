# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```sh
make               # compile + xref + eunit
make compile       # rebar3 compile
make xref          # rebar3 xref
make eunit         # rebar3 eunit
make dialyzer      # rebar3 dialyzer
make repl          # rebar3 shell
```

Run a single module's or single test's eunit tests:

```sh
rebar3 eunit --module=radix64
rebar3 eunit --test=epgp:enc_dec_test
```

Tests live inside the source modules in `-ifdef(TEST).` blocks at the bottom of
each file, not in a separate `test/` directory. `rebar3 eunit` defines `TEST`;
plain `rebar3 compile` does not, so test-only helpers must stay inside the ifdef.

CI (`.github/workflows/ci.yml`) runs compile → xref / eunit / dialyzer, plus a
matrix of OTP 27/28/29. Note the matrix job runs `rebar3 ct`, which currently
passes trivially because there are no Common Test suites.

## Releases

Pushes to `main` release automatically. The `versioner` job runs
`ietf-tools/semver-action` to derive the next version from the conventional
commits since the last tag, and `release` then runs `gh release create` once
xref, eunit, dialyzer and the OTP matrix pass.

- **Tags are bare version numbers — no `v` prefix** (`0.1.10`, not `v0.1.10`).
  The action's `prefix` input defaults to empty, so it reads existing tags
  as-is; the job publishes the `nextStrict` output, which is prefix-free.
- Bump is driven by commit type: `feat` minors; `fix`/`perf`/`refactor`/
  `chore`/`docs`/`build`/`ci`/`test` patches; a `!` marker or `BREAKING CHANGE`
  note majors. `patchAll` is deliberately not set, unlike in ek_teleadr.
- To skip a release, start the commit message with `no-release`. If no commit
  warrants a bump the version output is empty and `release` no-ops rather than
  failing the build.
- `src/epgp.app.src` uses `{vsn, git}`, so the app version comes from the git
  tag and must not be hardcoded. On a branch it resolves to a describe-style
  `0.1.10+build.40.ref0d00955`. (`{vsn, semver}` is a literal alias for `git`
  in `rebar_utils:vcs_vsn_cmd/3` — the two are interchangeable.)
- Because of that, **every CI job that builds needs `fetch-depth: 0`**. With
  the `actions/checkout` default of 1 no tags are fetched and rebar3 silently
  resolves the version to `0.0.0+build.1.ref<sha>` with no warning.

Note `xref_checks` includes `locals_not_used`, so an unused private function
fails the build — this is why several `*_tag/1` and `*_alg/1` clauses for
unimplemented algorithms are commented out rather than deleted.

## Architecture

A minimal OpenPGP (RFC 4880) library with no dependencies, implementing only
password-based symmetric encryption. Two modules:

**`radix64`** — OpenPGP's ASCII armor base64 variant. Differs from stdlib
`base64` in that `encode/1` splits at 64 chars per line and appends the
`=`-prefixed CRC-24 checksum footer; `decode/1` verifies that checksum and
returns `{error, {bad_crc24, _, _}}` on mismatch. The `b64d/1` and `b64e/1`
lookup tuples are lifted from OTP's `base64`.

**`epgp`** — packet framing plus the encrypt/parse pipeline.

Encrypt (`sym_encrypt/2` → `do_sym_encrypt/2`) builds nested packets
innermost-first and concatenates two top-level packets:

```
packet 3  (SKE session key)   — s2k(iter_salted, sha256) of password wraps a random session key
packet 18 (SE+IP data)        — AES-256-CFB128 over:
  packet 8  (compressed)      — raw deflate (ZIP)
    packet 11 (literal data)  — utf8, empty filename, unix timestamp
```

Parse (`parse/2`) is the exact inverse and returns a nested list of the
`#pgp_*{}` records. Records for every RFC 4880 packet tag are declared, but only
tags 3, 8, 11 and 18 have real parsers; everything else falls through to
`{Record, RawPacket}` in `parse_packet/3`.

State threads through both directions in `#pgp_ctx{}`, which carries the
password closure (`pw_fun`) on the way in and the recovered session key
(`skey`) once packet 3 has been processed — packet 18 then reads it from the
same context. Secrets are held in zero-arity closures rather than plain
binaries, and `s2k/5` forces a `garbage_collect/0` after key derivation.

Packet length encoding (`packet_len/1` / `find_length_new/3`) uses the RFC's
three-way new-format scheme (1 byte <192, 2 bytes <8384, 5 bytes above); the
`length_*_test` cases pin the boundaries. Old-format packets and partial
lengths are unsupported and raise.

Integrity on decrypt is checked three ways in `parse_se_n_ip_data/3`: the
repeated nonce checksum bytes, the `d3 14` MDC packet marker, and a SHA-1
digest compared with `const_time_eq/2`.

Only these algorithm choices are supported, and the mapping functions
(`sym_alg/1`, `hash_alg/1`, `comp_alg/1`, …) will fail-fast on anything else:
`iter_salted_s2k`, `aes_256_cfb128`, `sha256`, `zip`, utf8 literals.

## Conventions

- Erlang style: leading-comma lists/records, 4-space indent, ~72 column width.
- `epgp:testmsg/0` returns a fixture message encrypted with the password
  `<<"apa">>` — useful for checking parsing against GnuPG-produced output.
- Emacs backup files (`*~`) are checked in alongside some sources; ignore them
  and never edit them.
