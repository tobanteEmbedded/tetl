// SPDX-License-Identifier: BSL-1.0

#include <etl/complex.hpp>

#include <etl/concepts.hpp>
#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    CHECK(etl::tuple_size_v<etl::complex<T>> == 2);
    CHECK(etl::same_as<etl::tuple_element_t<0, etl::complex<T>>, T>);
    CHECK(etl::same_as<etl::tuple_element_t<1, etl::complex<T>>, T>);

    auto tc = etl::complex<T>{};
    CHECK(tc.real() == T(0));
    CHECK(tc.imag() == T(0));

    auto re = etl::complex<T>{T(1)};
    CHECK(re.real() == T(1));
    CHECK(re.imag() == T(0));

    auto im = etl::complex<T>{T(1), T(2)};
    CHECK(im.real() == T(1));
    CHECK(im.imag() == T(2));

    tc = re;
    CHECK(tc.real() == T(1));
    CHECK(tc.imag() == T(0));
    CHECK(etl::real(tc) == T(1));
    CHECK(etl::imag(tc) == T(0));
    CHECK(real(tc) == T(1)); // ADL
    CHECK(imag(tc) == T(0)); // ADL

    tc *= T(2);
    CHECK(tc.real() == T(2));
    CHECK(tc.imag() == T(0));

    tc.real(T(1));
    tc.imag(T(2));
    CHECK(tc.real() == T(1));
    CHECK(tc.imag() == T(2));

    // unary +
    tc = +tc;
    CHECK(tc.real() == T(1));
    CHECK(tc.imag() == T(2));

    // unary -
    tc = -tc;
    CHECK(tc.real() == T(-1));
    CHECK(tc.imag() == T(-2));

    // unary -
    tc = -tc;
    CHECK(tc.real() == T(1));
    CHECK(tc.imag() == T(2));

    // operator+
    auto sum = tc + tc;
    CHECK(sum.real() == T(2));
    CHECK(sum.imag() == T(4));

    // operator-
    auto diff = tc - sum;
    CHECK(diff.real() == T(-1));
    CHECK(diff.imag() == T(-2));

    // scaled_mul
    auto scaledMul = diff * T(2);
    CHECK(scaledMul.real() == T(-2));
    CHECK(scaledMul.imag() == T(-4));

    // scaled_div
    auto scaledDiv = scaledMul / T(2);
    CHECK(scaledDiv.real() == T(-1));
    CHECK(scaledDiv.imag() == T(-2));

    {
        using namespace etl::complex_literals;

        auto f = 2_if;
        CHECK(f.real() == 0.0F);
        CHECK(f.imag() == 2.0F);

        auto d = 2_i;
        CHECK(d.real() == 0.0);
        CHECK(d.imag() == 2.0);

        auto ld = 2_il;
        CHECK(ld.real() == 0.0L);
        CHECK(ld.imag() == 2.0L);
    }

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::int64_t>());
    CHECK(test<float>());
    CHECK(test<double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
