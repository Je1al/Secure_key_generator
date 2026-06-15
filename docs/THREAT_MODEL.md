# Threat model

This document states what SecureKeygen defends against, what it explicitly does
*not*, and the assumptions its security rests on. It is deliberately honest about
limits — an RNG that overstates its guarantees is worse than one that is clear
about them.

## Assets
- **Generated keys** and any password-derived keys.
- **DRBG internal state** (`K`/`V`, `Key`/`V`, `V`/`C`) — disclosure allows an
  attacker to predict future output until the next reseed.
- **Seed entropy** drawn from the OS.

## Security goals
1. **Unpredictability (forward).** Without knowledge of the internal state, output
   is computationally indistinguishable from random.
2. **Backtracking resistance.** Compromise of the current state does not reveal
   previously produced output. This follows from the one-way DRBG update
   functions defined in SP 800-90A.
3. **Recovery after reseed (prediction resistance on demand).** A reseed from a
   healthy OS source restores security after a state compromise.

## Trust assumptions
- **The OS CSPRNG is healthy and properly seeded.** `getrandom` / `getentropy` /
  `BCryptGenRandom` are the trust anchor. If the kernel pool is unseeded or
  backdoored, SecureKeygen inherits that weakness — as does every userspace RNG.
- **Process memory is private.** `secure_zero` reduces the window in which key
  material lingers, but an attacker who can read process memory in real time is
  out of scope.
- **The build toolchain is trusted** and does not optimize away the security
  wipes (a `volatile`-based barrier is used to discourage this).

## Adversaries considered
| Adversary | Mitigation |
|---|---|
| Predicts output without state knowledge | Standardized DRBG with ≥256-bit security strength; output validated against NIST CAVP vectors |
| Recovers state, then observes future output | Reseed from OS entropy (manual `reseed_from_os`, or automatic at the reseed interval) |
| Recovers state, then targets past output | One-way DRBG update ⇒ backtracking resistance |
| Feeds malformed input to the tools | Decoders reject by exception; fuzzed under ASan/UBSan |
| Exhausts/forecloses the entropy file descriptor | Syscall-based entropy avoids the `/dev/urandom` FD failure mode |

## Out of scope
- **Side channels.** The from-scratch AES uses S-box lookups and the math
  routines are not constant-time with respect to secret data. Timing / cache
  attacks against an attacker co-located on the same hardware are **not**
  defended against. (Tag comparison *is* constant-time.)
- **Fault injection / glitching** against an HSM or secure element.
- **Physical extraction** of RAM (cold-boot) or of the silicon RNG.
- **FIPS 140-3 / Common Criteria assurance.** None claimed.
- **Key storage, transport, and lifecycle.** This project produces key bytes; it
  does not store, wrap, escrow, or distribute them.

## Known limitations
- CTR-DRBG is implemented in the *no derivation function* configuration, which
  requires full-entropy 48-byte seed material; supplying lower-entropy input
  there would reduce strength. The CSPRNG facade always seeds it from the OS at
  full size.
- The SP 800-22 suite is a *subset*. Passing it is necessary, not sufficient,
  evidence of randomness quality.
- No protection against a compromised compiler or supply chain.

## Reporting
This is a personal educational project. If you spot a correctness or security
issue, please open an issue on the repository.
