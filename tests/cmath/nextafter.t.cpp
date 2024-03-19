// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include "testing/testing.hpp"

constexpr auto test() -> bool
{
    using etl::bit_cast;
    using etl::nextafter;
    using etl::nextafterf;
    using etl::uint32_t;
    using etl::uint64_t;

    CHECK(bit_cast<uint32_t>(nextafter(0.0F, 1.0F)) == 1U);

    CHECK(bit_cast<uint32_t>(nextafterf(1.0F, 1.0F)) == 1065353216U);
    CHECK(bit_cast<uint32_t>(nextafterf(1.0F, 0.0F)) == 1065353215U);
    CHECK(bit_cast<uint32_t>(nextafterf(1.0F, 2.0F)) == 1065353217U);

    CHECK(bit_cast<uint32_t>(nextafter(1.0F, 1.0F)) == 1065353216U);
    CHECK(bit_cast<uint32_t>(nextafter(1.0F, 0.0F)) == 1065353215U);
    CHECK(bit_cast<uint32_t>(nextafter(1.0F, 2.0F)) == 1065353217U);

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)
    CHECK(bit_cast<uint64_t>(nextafter(0.0, 1.0)) == 1U);
    CHECK(bit_cast<uint64_t>(nextafter(1.0, 1.0)) == 4607182418800017408U);
    CHECK(bit_cast<uint64_t>(nextafter(1.0, 0.0)) == 4607182418800017407U);
    CHECK(bit_cast<uint64_t>(nextafter(1.0, 2.0)) == 4607182418800017409U);
#endif

    return true;
}

auto main() -> int
{
    CHECK(test());

    // TODO
    // static_assert(test<long double>());
    // CHECK(test<long double>());
    // static_assert(test<float>());
    // static_assert(test<double>());
    return 0;
}
