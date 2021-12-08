/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/cmath.hpp"

#include "testing/testing.hpp"

constexpr auto test() -> bool
{
    using etl::bit_cast;
    using etl::nextafter;
    using etl::nextafterf;
    using etl::uint32_t;
    using etl::uint64_t;

    assert(bit_cast<uint32_t>(nextafter(0.0F, 1.0F)) == 1U);

    assert(bit_cast<uint32_t>(nextafterf(1.0F, 1.0F)) == 1065353216U);
    assert(bit_cast<uint32_t>(nextafterf(1.0F, 0.0F)) == 1065353215U);
    assert(bit_cast<uint32_t>(nextafterf(1.0F, 2.0F)) == 1065353217U);

    assert(bit_cast<uint32_t>(nextafter(1.0F, 1.0F)) == 1065353216U);
    assert(bit_cast<uint32_t>(nextafter(1.0F, 0.0F)) == 1065353215U);
    assert(bit_cast<uint32_t>(nextafter(1.0F, 2.0F)) == 1065353217U);

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)
    assert(bit_cast<uint64_t>(nextafter(0.0, 1.0)) == 1U);
    assert(bit_cast<uint64_t>(nextafter(1.0, 1.0)) == 4607182418800017408U);
    assert(bit_cast<uint64_t>(nextafter(1.0, 0.0)) == 4607182418800017407U);
    assert(bit_cast<uint64_t>(nextafter(1.0, 2.0)) == 4607182418800017409U);
#endif

    return true;
}

auto main() -> int
{
    assert(test());

    // TODO
    // static_assert(test<long double>());
    // assert(test<long double>());
    // static_assert(test<float>());
    // static_assert(test<double>());
    return 0;
}