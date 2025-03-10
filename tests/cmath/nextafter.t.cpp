// SPDX-License-Identifier: BSL-1.0

#include <etl/cmath.hpp>

#include "testing/testing.hpp"

static constexpr auto test() -> bool
{
    CHECK(etl::bit_cast<etl::uint32_t>(etl::nextafter(0.0F, 1.0F)) == 1U);

    CHECK(etl::bit_cast<etl::uint32_t>(etl::nextafterf(1.0F, 1.0F)) == 1065353216U);
    CHECK(etl::bit_cast<etl::uint32_t>(etl::nextafterf(1.0F, 0.0F)) == 1065353215U);
    CHECK(etl::bit_cast<etl::uint32_t>(etl::nextafterf(1.0F, 2.0F)) == 1065353217U);

    CHECK(etl::bit_cast<etl::uint32_t>(etl::nextafter(1.0F, 1.0F)) == 1065353216U);
    CHECK(etl::bit_cast<etl::uint32_t>(etl::nextafter(1.0F, 0.0F)) == 1065353215U);
    CHECK(etl::bit_cast<etl::uint32_t>(etl::nextafter(1.0F, 2.0F)) == 1065353217U);

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)
    CHECK(etl::bit_cast<etl::uint64_t>(etl::nextafter(0.0, 1.0)) == 1U);
    CHECK(etl::bit_cast<etl::uint64_t>(etl::nextafter(1.0, 1.0)) == 4607182418800017408U);
    CHECK(etl::bit_cast<etl::uint64_t>(etl::nextafter(1.0, 0.0)) == 4607182418800017407U);
    CHECK(etl::bit_cast<etl::uint64_t>(etl::nextafter(1.0, 2.0)) == 4607182418800017409U);
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
