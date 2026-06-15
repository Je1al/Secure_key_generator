#ifndef SECUREKG_STATS_SPECIAL_FUNCTIONS_H_
#define SECUREKG_STATS_SPECIAL_FUNCTIONS_H_

#include <cmath>

// Numerical special functions needed for the SP 800-22 p-values: the
// regularized incomplete gamma functions (chi-square tail) and the standard
// normal CDF. The incomplete gamma routines are the classic Cephes algorithms
// (series expansion for the lower tail, continued fraction for the upper tail),
// which match the reference C used by the NIST STS.
namespace securekg::stats::detail {

constexpr double kMachEp = 1.11022302462515654042e-16;
constexpr double kMaxLog = 7.09782712893383996732e2;
constexpr double kBig = 4.503599627370496e15;
constexpr double kBigInv = 2.22044604925031308085e-16;

inline double igamc(double a, double x);  // upper tail Q(a, x)

// Lower regularized incomplete gamma P(a, x).
inline double igam(double a, double x) {
  if (x <= 0.0 || a <= 0.0) return 0.0;
  if (x > 1.0 && x > a) return 1.0 - igamc(a, x);

  double ax = a * std::log(x) - x - std::lgamma(a);
  if (ax < -kMaxLog) return 0.0;
  ax = std::exp(ax);

  double r = a, c = 1.0, ans = 1.0;
  do {
    r += 1.0;
    c *= x / r;
    ans += c;
  } while (c / ans > kMachEp);

  return ans * ax / a;
}

// Upper regularized incomplete gamma Q(a, x) = 1 - P(a, x).
inline double igamc(double a, double x) {
  if (x <= 0.0 || a <= 0.0) return 1.0;
  if (x < 1.0 || x < a) return 1.0 - igam(a, x);

  double ax = a * std::log(x) - x - std::lgamma(a);
  if (ax < -kMaxLog) return 0.0;
  ax = std::exp(ax);

  double y = 1.0 - a;
  double z = x + y + 1.0;
  double c = 0.0;
  double pkm2 = 1.0, qkm2 = x;
  double pkm1 = x + 1.0, qkm1 = z * x;
  double ans = pkm1 / qkm1;
  double t;
  do {
    c += 1.0;
    y += 1.0;
    z += 2.0;
    double yc = y * c;
    double pk = pkm1 * z - pkm2 * yc;
    double qk = qkm1 * z - qkm2 * yc;
    if (qk != 0.0) {
      double r = pk / qk;
      t = std::fabs((ans - r) / r);
      ans = r;
    } else {
      t = 1.0;
    }
    pkm2 = pkm1;
    pkm1 = pk;
    qkm2 = qkm1;
    qkm1 = qk;
    if (std::fabs(pk) > kBig) {
      pkm2 *= kBigInv;
      pkm1 *= kBigInv;
      qkm2 *= kBigInv;
      qkm1 *= kBigInv;
    }
  } while (t > kMachEp);

  return ans * ax;
}

// Standard normal cumulative distribution function.
inline double normal_cdf(double x) {
  return 0.5 * std::erfc(-x / std::sqrt(2.0));
}

}  // namespace securekg::stats::detail

#endif  // SECUREKG_STATS_SPECIAL_FUNCTIONS_H_
