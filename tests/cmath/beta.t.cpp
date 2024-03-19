// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include "testing/approx.hpp"
#include "testing/testing.hpp"

namespace {
template <typename T>
constexpr auto binom(int n, int k) -> T
{
    auto const tmp = 1 / ((n + 1) * etl::beta(n - k + 1, k + 1));
    return static_cast<T>(tmp);
}

template <typename T>
constexpr auto test() -> bool
{
    ASSERT_APPROX(binom<T>(1, 1), T(1));
    return true;
}
} // namespace

auto main() -> int
{
    static_assert(test<float>());
    static_assert(test<double>());
    static_assert(test<long double>());
    ASSERT(test<float>());
    ASSERT(test<double>());
    ASSERT(test<long double>());
    return 0;
}
