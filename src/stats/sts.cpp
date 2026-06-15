#include "securekg/stats/sts.h"

#include <algorithm>
#include <cmath>

#include "special_functions.h"

namespace securekg::stats {

using detail::igamc;
using detail::normal_cdf;

Bits bytes_to_bits(const Bytes& data) {
  Bits bits;
  bits.reserve(data.size() * 8);
  for (std::uint8_t byte : data)
    for (int i = 7; i >= 0; --i) bits.push_back((byte >> i) & 1u);
  return bits;
}

// --- 2.1 Frequency (Monobit) Test ------------------------------------------
TestResult frequency_monobit(const Bits& bits, double alpha) {
  TestResult r;
  r.name = "Frequency (Monobit)";
  std::size_t n = bits.size();
  if (n == 0) {
    r.detail = "empty input";
    return r;
  }
  long long s = 0;
  for (std::uint8_t b : bits) s += b ? 1 : -1;
  double s_obs = std::fabs(static_cast<double>(s)) / std::sqrt(static_cast<double>(n));
  r.p_value = std::erfc(s_obs / std::sqrt(2.0));
  r.applicable = true;
  r.passed = r.p_value >= alpha;
  r.detail = "n=" + std::to_string(n);
  return r;
}

// --- 2.2 Frequency Test within a Block -------------------------------------
TestResult block_frequency(const Bits& bits, std::size_t M, double alpha) {
  TestResult r;
  r.name = "Block Frequency";
  std::size_t n = bits.size();
  std::size_t N = M ? n / M : 0;
  if (M < 1 || N < 1) {
    r.detail = "insufficient data";
    return r;
  }
  double chi = 0.0;
  for (std::size_t i = 0; i < N; ++i) {
    std::size_t ones = 0;
    for (std::size_t j = 0; j < M; ++j) ones += bits[i * M + j];
    double pi = static_cast<double>(ones) / static_cast<double>(M);
    chi += (pi - 0.5) * (pi - 0.5);
  }
  chi *= 4.0 * static_cast<double>(M);
  r.p_value = igamc(static_cast<double>(N) / 2.0, chi / 2.0);
  r.applicable = true;
  r.passed = r.p_value >= alpha;
  r.detail = "M=" + std::to_string(M) + ", N=" + std::to_string(N);
  return r;
}

// --- 2.3 Runs Test ----------------------------------------------------------
TestResult runs(const Bits& bits, double alpha) {
  TestResult r;
  r.name = "Runs";
  std::size_t n = bits.size();
  if (n < 2) {
    r.detail = "insufficient data";
    return r;
  }
  std::size_t ones = 0;
  for (std::uint8_t b : bits) ones += b;
  double pi = static_cast<double>(ones) / static_cast<double>(n);
  double tau = 2.0 / std::sqrt(static_cast<double>(n));
  r.applicable = true;
  if (std::fabs(pi - 0.5) >= tau) {
    // Monobit precondition failed -> the test reports p-value 0.
    r.p_value = 0.0;
    r.passed = false;
    r.detail = "monobit precondition failed (pi=" + std::to_string(pi) + ")";
    return r;
  }
  std::size_t v = 1;
  for (std::size_t k = 1; k < n; ++k)
    if (bits[k] != bits[k - 1]) ++v;
  double num = std::fabs(static_cast<double>(v) -
                         2.0 * n * pi * (1.0 - pi));
  double den = 2.0 * std::sqrt(2.0 * static_cast<double>(n)) * pi * (1.0 - pi);
  r.p_value = std::erfc(num / den);
  r.passed = r.p_value >= alpha;
  r.detail = "runs=" + std::to_string(v);
  return r;
}

// --- 2.4 Longest Run of Ones in a Block ------------------------------------
TestResult longest_run_of_ones(const Bits& bits, double alpha) {
  TestResult r;
  r.name = "Longest Run of Ones";
  std::size_t n = bits.size();

  std::size_t M, K;
  std::vector<double> pi;
  std::vector<std::size_t> bounds;  // upper bounds for classes 0..K-1
  if (n < 128) {
    r.detail = "insufficient data (need >= 128 bits)";
    return r;
  } else if (n < 6272) {
    M = 8;
    K = 3;
    pi = {0.21484375, 0.3671875, 0.23046875, 0.1875};
    bounds = {1, 2, 3};  // <=1, ==2, ==3, >=4
  } else if (n < 750000) {
    M = 128;
    K = 5;
    pi = {0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124};
    bounds = {4, 5, 6, 7, 8};  // <=4 .. >=9
  } else {
    M = 10000;
    K = 6;
    pi = {0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727};
    bounds = {10, 11, 12, 13, 14, 15};
  }

  std::size_t N = n / M;
  std::vector<std::size_t> v(K + 1, 0);
  for (std::size_t i = 0; i < N; ++i) {
    std::size_t longest = 0, cur = 0;
    for (std::size_t j = 0; j < M; ++j) {
      if (bits[i * M + j]) {
        ++cur;
        if (cur > longest) longest = cur;
      } else {
        cur = 0;
      }
    }
    std::size_t cls = K;  // default to the last "(>=)" class
    for (std::size_t c = 0; c < bounds.size(); ++c) {
      if (longest <= bounds[c]) {
        cls = c;
        break;
      }
    }
    ++v[cls];
  }

  double chi = 0.0;
  for (std::size_t c = 0; c <= K; ++c) {
    double expected = static_cast<double>(N) * pi[c];
    double d = static_cast<double>(v[c]) - expected;
    chi += d * d / expected;
  }
  r.p_value = igamc(static_cast<double>(K) / 2.0, chi / 2.0);
  r.applicable = true;
  r.passed = r.p_value >= alpha;
  r.detail = "M=" + std::to_string(M) + ", N=" + std::to_string(N);
  return r;
}

// --- 2.13 Cumulative Sums (Cusum) Test -------------------------------------
namespace {
double cusum_pvalue(std::size_t n, long long z_ll) {
  double z = static_cast<double>(z_ll);
  double sqn = std::sqrt(static_cast<double>(n));
  if (z == 0.0) return 1.0;

  double sum1 = 0.0;
  long long lo = static_cast<long long>(std::floor((-static_cast<double>(n) / z + 1.0) / 4.0));
  long long hi = static_cast<long long>(std::floor((static_cast<double>(n) / z - 1.0) / 4.0));
  for (long long k = lo; k <= hi; ++k) {
    sum1 += normal_cdf(((4.0 * k + 1.0) * z) / sqn);
    sum1 -= normal_cdf(((4.0 * k - 1.0) * z) / sqn);
  }
  double sum2 = 0.0;
  lo = static_cast<long long>(std::floor((-static_cast<double>(n) / z - 3.0) / 4.0));
  for (long long k = lo; k <= hi; ++k) {
    sum2 += normal_cdf(((4.0 * k + 3.0) * z) / sqn);
    sum2 -= normal_cdf(((4.0 * k + 1.0) * z) / sqn);
  }
  double p = 1.0 - sum1 + sum2;
  if (p < 0.0) p = 0.0;
  if (p > 1.0) p = 1.0;
  return p;
}
}  // namespace

std::vector<TestResult> cumulative_sums(const Bits& bits, double alpha) {
  std::size_t n = bits.size();
  std::vector<TestResult> out(2);
  out[0].name = "Cumulative Sums (forward)";
  out[1].name = "Cumulative Sums (backward)";
  if (n < 1) {
    out[0].detail = out[1].detail = "empty input";
    return out;
  }

  long long s = 0, zf = 0, zb = 0;
  for (std::size_t i = 0; i < n; ++i) {
    s += bits[i] ? 1 : -1;
    zf = std::max(zf, std::llabs(s));
  }
  s = 0;
  for (std::size_t i = 0; i < n; ++i) {
    s += bits[n - 1 - i] ? 1 : -1;
    zb = std::max(zb, std::llabs(s));
  }

  out[0].applicable = out[1].applicable = true;
  out[0].p_value = cusum_pvalue(n, zf);
  out[1].p_value = cusum_pvalue(n, zb);
  out[0].passed = out[0].p_value >= alpha;
  out[1].passed = out[1].p_value >= alpha;
  out[0].detail = "z=" + std::to_string(zf);
  out[1].detail = "z=" + std::to_string(zb);
  return out;
}

// --- 2.12 Approximate Entropy Test -----------------------------------------
namespace {
// phi^(m): -sum over occurring m-bit patterns of C_j * ln C_j, using the
// circularly augmented sequence.
double approx_phi(const Bits& bits, std::size_t m) {
  std::size_t n = bits.size();
  if (m == 0) return 0.0;
  std::size_t size = std::size_t(1) << m;
  std::vector<std::size_t> count(size, 0);
  std::size_t mask = size - 1;
  for (std::size_t i = 0; i < n; ++i) {
    std::size_t pattern = 0;
    for (std::size_t j = 0; j < m; ++j)
      pattern = ((pattern << 1) | bits[(i + j) % n]) & mask;
    ++count[pattern];
  }
  double phi = 0.0;
  for (std::size_t c : count)
    if (c > 0) {
      double cj = static_cast<double>(c) / static_cast<double>(n);
      phi += cj * std::log(cj);
    }
  return phi;
}
}  // namespace

TestResult approximate_entropy(const Bits& bits, std::size_t m, double alpha) {
  TestResult r;
  r.name = "Approximate Entropy";
  std::size_t n = bits.size();
  if (m < 1 || n < (std::size_t(1) << (m + 2))) {
    r.detail = "insufficient data for m=" + std::to_string(m);
    return r;
  }
  double phi_m = approx_phi(bits, m);
  double phi_m1 = approx_phi(bits, m + 1);
  double apen = phi_m - phi_m1;
  double chi = 2.0 * static_cast<double>(n) * (std::log(2.0) - apen);
  r.p_value = igamc(std::pow(2.0, static_cast<double>(m) - 1.0), chi / 2.0);
  r.applicable = true;
  r.passed = r.p_value >= alpha;
  r.detail = "m=" + std::to_string(m);
  return r;
}

// --- 2.11 Serial Test -------------------------------------------------------
namespace {
double serial_psi2(const Bits& bits, std::size_t m) {
  std::size_t n = bits.size();
  if (m == 0) return 0.0;
  std::size_t size = std::size_t(1) << m;
  std::vector<std::size_t> count(size, 0);
  std::size_t mask = size - 1;
  for (std::size_t i = 0; i < n; ++i) {
    std::size_t pattern = 0;
    for (std::size_t j = 0; j < m; ++j)
      pattern = ((pattern << 1) | bits[(i + j) % n]) & mask;
    ++count[pattern];
  }
  double sum = 0.0;
  for (std::size_t c : count) sum += static_cast<double>(c) * static_cast<double>(c);
  return (static_cast<double>(size) / static_cast<double>(n)) * sum -
         static_cast<double>(n);
}
}  // namespace

std::vector<TestResult> serial(const Bits& bits, std::size_t m, double alpha) {
  std::vector<TestResult> out(2);
  out[0].name = "Serial (p-value 1)";
  out[1].name = "Serial (p-value 2)";
  std::size_t n = bits.size();
  if (m < 3 || n < (std::size_t(1) << (m + 2))) {
    out[0].detail = out[1].detail = "insufficient data for m=" + std::to_string(m);
    return out;
  }
  double psi_m = serial_psi2(bits, m);
  double psi_m1 = serial_psi2(bits, m - 1);
  double psi_m2 = serial_psi2(bits, m - 2);
  double del1 = psi_m - psi_m1;
  double del2 = psi_m - 2.0 * psi_m1 + psi_m2;
  out[0].p_value = igamc(std::pow(2.0, static_cast<double>(m) - 2.0), del1 / 2.0);
  out[1].p_value = igamc(std::pow(2.0, static_cast<double>(m) - 3.0), del2 / 2.0);
  out[0].applicable = out[1].applicable = true;
  out[0].passed = out[0].p_value >= alpha;
  out[1].passed = out[1].p_value >= alpha;
  out[0].detail = out[1].detail = "m=" + std::to_string(m);
  return out;
}

// --- Orchestration ----------------------------------------------------------
std::vector<TestResult> run_all(const Bytes& data, double alpha) {
  Bits bits = bytes_to_bits(data);
  std::size_t n = bits.size();
  std::vector<TestResult> results;

  results.push_back(frequency_monobit(bits, alpha));

  std::size_t M = std::max<std::size_t>(20, n / 99 + 1);
  results.push_back(block_frequency(bits, M, alpha));

  results.push_back(runs(bits, alpha));
  results.push_back(longest_run_of_ones(bits, alpha));

  auto cs = cumulative_sums(bits, alpha);
  results.insert(results.end(), cs.begin(), cs.end());

  // Pick a block length m valid for the input size: 2^(m+2) <= n.
  std::size_t m = 2;
  while ((std::size_t(1) << (m + 3)) <= n && m < 10) ++m;

  results.push_back(approximate_entropy(bits, m, alpha));
  auto se = serial(bits, m, alpha);
  results.insert(results.end(), se.begin(), se.end());

  return results;
}

}  // namespace securekg::stats
