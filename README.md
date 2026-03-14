# Secure Key Generator (secure_keygen)

Secure Key Generator is a C++ cybersecurity project that produces cryptographically strong keys using system entropy, SHA-based mixing, and basic statistical tests. The repository is structured for portfolio use and emphasizes security-focused engineering practices.

## Project Goals

- Generate cryptographically secure random keys
- Use multiple system entropy sources
- Strengthen randomness with SHA-256 mixing
- Evaluate output quality with entropy and randomness tests
- Provide key output in hex, binary, and base64 formats

## How It Works

### Cryptographically Secure Randomness
Cryptographically secure random numbers are unpredictable even if an attacker knows previous outputs. This project uses operating system entropy sources (e.g., `/dev/urandom` or `std::random_device`) and mixes in timing, process, and memory-state inputs to maximize unpredictability.

### Entropy and Mixing
Entropy is collected from multiple independent sources and then processed through SHA-256. Hashing improves randomness by:

- Compressing varied inputs into a fixed-size, uniform output
- Diffusing small changes across the entire output
- Reducing structural bias in the entropy pool

### Entropy Tests
The project includes a Shannon entropy test, which measures how close the byte distribution is to uniform randomness. For perfectly random bytes, the entropy approaches **8.0 bits/byte**.

### Randomness Tests
The randomness module performs basic statistical checks:

- **Frequency (Monobit) Test**: checks balance of 0s and 1s
- **Runs Test**: checks how often the bits switch between 0 and 1
- **Bit Distribution Test**: checks bias per bit position (bit 0 through bit 7)

These tests are informative but **not a substitute** for formal cryptographic validation.

## Repository Structure

```
secure_keygen/
├── entropy_collector.cpp
├── entropy_collector.h
├── entropy_test.cpp
├── entropy_test.h
├── keygen.cpp
├── keygen.h
├── main.cpp
├── randomness_test.cpp
├── randomness_test.h
├── sha_mixer.cpp
├── sha_mixer.h
└── README.md
```

## Build and Run

Requirements: a C++17-capable compiler (e.g., `g++` or `clang++`).

```
g++ -std=c++17 -O2 -Wall -Wextra -pedantic \
  entropy_collector.cpp sha_mixer.cpp keygen.cpp \
  entropy_test.cpp randomness_test.cpp main.cpp \
  -o secure_keygen

./secure_keygen
```

## Example Output (Abbreviated)

- 128-bit, 256-bit, and 512-bit keys
- Entropy test results
- Monobit, runs, and bit-distribution tests

## Limitations of Pseudo-Random Generators
Pseudo-random generators (PRNGs) are deterministic and can be predicted if their state is compromised. This project avoids traditional PRNGs by using operating system entropy and cryptographic hashing to produce non-deterministic outputs.

## Advanced Improvements (Future Work)

- Integrate hardware RNGs (e.g., Intel RDSEED/RDRAND)
- Use OS APIs directly (`/dev/random`, `getrandom()`, `BCryptGenRandom`, `CryptGenRandom`)
- Support alternate hashing (SHA-512, SHA-3)
- Implement full NIST SP 800-22 randomness tests
- Add continuous entropy health checks and reseeding

## Security Notes

- This project is educational and demonstrates sound key generation practices.
- For production systems, prefer vetted cryptographic libraries and system APIs.
- The included statistical tests offer only basic assurance and should not be treated as proof of security.
