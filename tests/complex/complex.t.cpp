// SPDX-License-Identifier: BSL-1.0

#include <etl/complex.hpp>

#include <etl/concepts.hpp>
#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    assert(etl::tuple_size_v<etl::complex<T>> == 2);
    assert(etl::same_as<etl::tuple_element_t<0, etl::complex<T>>, T>);
    assert(etl::same_as<etl::tuple_element_t<1, etl::complex<T>>, T>);

    auto tc = etl::complex<T> {};
    assert(tc.real() == T(0));
    assert(tc.imag() == T(0));

    auto re = etl::complex<T> {T(1)};
    assert(re.real() == T(1));
    assert(re.imag() == T(0));

    auto im = etl::complex<T> {T(1), T(2)};
    assert(im.real() == T(1));
    assert(im.imag() == T(2));

    tc = re;
    assert(tc.real() == T(1));
    assert(tc.imag() == T(0));
    assert(etl::real(tc) == T(1));
    assert(etl::imag(tc) == T(0));
    assert(real(tc) == T(1)); // ADL
    assert(imag(tc) == T(0)); // ADL

    tc *= T(2);
    assert(tc.real() == T(2));
    assert(tc.imag() == T(0));

    tc.real(T(1));
    tc.imag(T(2));
    assert(tc.real() == T(1));
    assert(tc.imag() == T(2));

    // unary +
    tc = +tc;
    assert(tc.real() == T(1));
    assert(tc.imag() == T(2));

    // unary -
    tc = -tc;
    assert(tc.real() == T(-1));
    assert(tc.imag() == T(-2));

    // unary -
    tc = -tc;
    assert(tc.real() == T(1));
    assert(tc.imag() == T(2));

    // operator+
    auto sum = tc + tc;
    assert(sum.real() == T(2));
    assert(sum.imag() == T(4));

    // operator-
    auto diff = tc - sum;
    assert(diff.real() == T(-1));
    assert(diff.imag() == T(-2));

    // scaled_mul
    auto scaledMul = diff * T(2);
    assert(scaledMul.real() == T(-2));
    assert(scaledMul.imag() == T(-4));

    // scaled_div
    auto scaledDiv = scaledMul / T(2);
    assert(scaledDiv.real() == T(-1));
    assert(scaledDiv.imag() == T(-2));

    {
        using namespace etl::complex_literals;

        auto f = 2_if;
        assert(f.real() == 0.0F);
        assert(f.imag() == 2.0F);

        auto d = 2_i;
        assert(d.real() == 0.0);
        assert(d.imag() == 2.0);

        auto ld = 2_il;
        assert(ld.real() == 0.0L);
        assert(ld.imag() == 2.0L);
    }

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::int8_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::int64_t>());
    assert(test<float>());
    assert(test<double>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}
