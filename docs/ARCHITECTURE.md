# Architecture

SecureKeygen is layered so that each tier depends only on the ones below it. The
flow of trust runs bottom-to-top: an OS entropy source seeds a standardized
DRBG, the DRBG drives a CSPRNG facade, and key generation / formatting sits on
top. The statistical and entropy-assessment tools observe the output rather than
participate in producing it.

```
                 ┌─────────────────────────────────────────┐
   tools/        │  securekg CLI  (keygen, derive, test,    │
                 │                 entropy, drbg, selftest)  │
                 └───────────────────┬─────────────────────-┘
                                     │
   keygen/       ┌───────────────────┴───────────────────┐
                 │  Csprng facade  ·  key formatting       │
                 │  (auto-reseed, per-request chunking)    │
                 └───────┬─────────────────────┬───────────┘
                         │                     │
   drbg/        ┌────────┴─────────┐           │  observes
                │ HMAC-DRBG        │           │
                │ Hash-DRBG        │   stats/  ┌┴───────────────────┐
                │ CTR-DRBG (AES)   │           │ SP 800-22 tests    │
                │ (SP 800-90A)     │           │ SP 800-90B MCV     │
                └────────┬─────────┘           └────────────────────┘
                         │ seeds
   entropy/     ┌────────┴─────────────────────────────────┐
                │ os_random: getrandom / getentropy /        │
                │ BCryptGenRandom (+ /dev/urandom fallback)  │
                └────────┬──────────────────────────────────┘
                         │ uses
   crypto/      ┌────────┴──────────────────────────────────┐
                │ SHA-256 · HMAC · HKDF · PBKDF2 · AES        │
                └───────────────────────────────────────────-┘
   util/          encoding · constant-time compare · secure_zero
```

## Modules

### `crypto/` — primitives
From-scratch implementations of the building blocks, each with a streaming
interface where it matters (SHA-256 and HMAC can be `update()`-ed incrementally,
which the DRBGs rely on).

- `Sha256` — FIPS 180-4, streaming.
- `HmacSha256` — FIPS 198-1 / RFC 2104, streaming, with the long-key reduction.
- `hkdf_*`, `pbkdf2_hmac_sha256` — RFC 5869 / RFC 8018.
- `Aes` — FIPS 197, encryption direction only (all the CTR-DRBG and CTR keystream
  need); 128/192/256-bit keys; ECB block + a CTR helper.

### `entropy/` — sources and assessment
- `os_random` — the only place that touches the operating system RNG. Uses
  syscalls; the file-based path is a guarded fallback.
- `estimate_entropy` — SP 800-90B Most Common Value min-entropy estimator plus
  Shannon entropy for context.

### `drbg/` — SP 800-90A mechanisms
A single `Drbg` interface (`generate` / `reseed` / `reseed_counter` /
`security_strength`) with three implementations. Generate throws
`Drbg::ReseedRequired` once the reseed interval (2⁴⁸ requests) is exceeded; the
CSPRNG catches it and reseeds. Implementation notes:

- **HMAC-DRBG** — the classic `K`/`V` update construction.
- **Hash-DRBG** — `seedlen = 440` bits; uses `Hash_df` and big-endian modular
  addition over the 55-byte state.
- **CTR-DRBG** — AES-256 *without* a derivation function, so seed material must be
  exactly `keylen + blocklen = 48` bytes at full entropy.

### `stats/` — SP 800-22 test suite
Each test returns a `TestResult { name, applicable, p_value, passed, detail }`.
P-values come from `std::erfc` and a Cephes-style regularized incomplete gamma
function (`igamc`) in `special_functions.h`, matching the reference NIST STS C.

### `keygen/` — the facade
`Csprng` ties a chosen DRBG to the OS entropy source, handles per-mechanism seed
sizing (32-byte entropy + 16-byte nonce for HMAC/Hash; exactly 48 bytes for CTR),
splits large requests to respect the SP 800-90A per-request limit, and reseeds on
demand. `from_seed(...)` builds a deterministic instance for reproducible output
and the test vectors.

### `selftest.cpp` — runtime known-answer tests
Embeds the FIPS / RFC / NIST CAVP vectors and runs them on demand, so correctness
can be re-verified in the field, not only at build time. Both the CLI
`selftest` command and the unit-test binary call `run_self_tests()`.

## Build topology
`src/**/*.cpp` compiles into a single static library `libsecurekg.a`. The CLI and
the test binary link against it. Make and CMake produce identical artifacts; CI
exercises both, plus ASan/UBSan and the libFuzzer harnesses.
