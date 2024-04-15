// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RANDOM_GENERATE_CANONICAL_HPP
#define TETL_RANDOM_GENERATE_CANONICAL_HPP

#include <etl/_algorithm/max.hpp>
#include <etl/_algorithm/min.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_cstdint/uint_t.hpp>
#include <etl/_limits/numeric_limits.hpp>

namespace etl {

namespace detail {

[[nodiscard]] constexpr auto generate_canonical_iterations(int bits, uint64_t gMin, uint64_t gMax) -> int
{
    if (bits == 0 || (gMax == numeric_limits<uint64_t>::max() && gMin == 0)) {
        return 1;
    }

    auto const range  = (gMax - gMin) + 1;
    auto const target = ~uint64_t{0} >> (64 - bits);

    auto product = uint64_t{1};
    auto ceiling = int{0};

    while (product <= target) {
        ++ceiling;
        if (product > numeric_limits<uint64_t>::max() / range) {
            break;
        }
        product *= range;
    }

    return ceiling;
}

} // namespace detail

/// \brief Generates a random floating point number in range [0,1).
/// \ingroup random
template <typename Real, size_t Bits, typename RNG>
[[nodiscard]] constexpr auto generate_canonical(RNG& g) noexcept(noexcept(g())) -> Real
{
    constexpr auto digits  = static_cast<size_t>(numeric_limits<Real>::digits);
    constexpr auto minBits = static_cast<int>(digits < Bits ? digits : Bits);

    auto const r = (static_cast<Real>(RNG::max()) - static_cast<Real>(RNG::min())) + Real{1};
    auto const k = detail::generate_canonical_iterations(minBits, RNG::min(), RNG::max());

    auto result = Real{0};
    auto factor = Real{1};

    for (int i = 0; i < k; ++i) {
        result += (static_cast<Real>(g()) - RNG::min()) * factor;
        factor *= r;
    }

    return result / factor;
}

} // namespace etl

#endif // TETL_RANDOM_GENERATE_CANONICAL_HPP
