/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/numbers.hpp"

#include "helper.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert((approx(etl::numbers::e_v<T>, T(2.7182818))));
    assert((approx(etl::numbers::log2e_v<T>, T(1.44269504))));
    assert((approx(etl::numbers::log10e_v<T>, T(0.4342944))));
    assert((approx(etl::numbers::pi_v<T>, T(3.1415926))));
    assert((approx(etl::numbers::inv_sqrtpi_v<T>, T(0.5641895))));
    assert((approx(etl::numbers::inv_pi_v<T>, T(0.3183098))));
    assert((approx(etl::numbers::ln2_v<T>, T(0.6931471))));
    assert((approx(etl::numbers::ln10_v<T>, T(2.3025850))));
    assert((approx(etl::numbers::sqrt2_v<T>, T(1.4142135))));
    assert((approx(etl::numbers::sqrt3_v<T>, T(1.7320508))));
    assert((approx(etl::numbers::inv_sqrt3_v<T>, T(0.5773502))));
    assert((approx(etl::numbers::egamma_v<T>, T(0.5772156))));
    assert((approx(etl::numbers::phi_v<T>, T(1.6180339))));

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<float>());
    assert(test<double>());
    return true;
}

auto main() -> int
{
    assert(test_all());
    // static_assert(test_all());
    return 0;
}