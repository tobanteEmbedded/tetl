// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl.concepts;
import etl.cstdint;
#else
    #include <etl/concepts.hpp>
    #include <etl/cstdint.hpp>
#endif

namespace {
constexpr auto floating_point_test(etl::floating_point auto /*v*/) { return true; }

constexpr auto floating_point_test(auto /*v*/) { return false; }

constexpr auto integral_test(etl::integral auto /*v*/) { return true; }

constexpr auto integral_test(auto /*v*/) { return false; }

constexpr auto signed_integral_test(etl::signed_integral auto /*v*/) { return true; }

constexpr auto signed_integral_test(auto /*v*/) { return false; }

constexpr auto unsigned_integral_test(etl::unsigned_integral auto /*v*/) { return true; }

constexpr auto unsigned_integral_test(auto /*v*/) { return false; }

constexpr auto destructible_test(etl::destructible auto /*v*/) { return true; }

[[maybe_unused]] constexpr auto destructible_test(auto /*v*/) { return false; }
} // namespace

static constexpr auto test() -> bool
{
    CHECK(floating_point_test(143.0));
    CHECK(floating_point_test(143.0F));
    CHECK(floating_point_test(143.0L));

    CHECK_FALSE(floating_point_test(etl::int8_t(42)));
    CHECK_FALSE(floating_point_test(etl::uint8_t(42)));
    CHECK_FALSE(floating_point_test(etl::int16_t(143)));
    CHECK_FALSE(floating_point_test(etl::uint16_t(143)));
    CHECK_FALSE(floating_point_test(etl::int32_t(143)));
    CHECK_FALSE(floating_point_test(etl::uint32_t(143)));
    CHECK_FALSE(floating_point_test(etl::int64_t(143)));
    CHECK_FALSE(floating_point_test(etl::uint64_t(143)));
    CHECK_FALSE(floating_point_test(143));
    CHECK_FALSE(floating_point_test(143U));

    CHECK(integral_test(etl::int8_t(42)));
    CHECK(integral_test(etl::uint8_t(42)));
    CHECK(integral_test(etl::int16_t(143)));
    CHECK(integral_test(etl::uint16_t(143)));
    CHECK(integral_test(etl::int32_t(143)));
    CHECK(integral_test(etl::uint32_t(143)));
    CHECK(integral_test(etl::int64_t(143)));
    CHECK(integral_test(etl::uint64_t(143)));
    CHECK(integral_test(143));
    CHECK(integral_test(143U));

    CHECK_FALSE(integral_test(143.0));
    CHECK_FALSE(integral_test(143.0F));
    CHECK_FALSE(integral_test(143.0L));

    CHECK(signed_integral_test(etl::int8_t(42)));
    CHECK(signed_integral_test(etl::int16_t(143)));
    CHECK(signed_integral_test(etl::int32_t(143)));
    CHECK(signed_integral_test(etl::int64_t(143)));
    CHECK(signed_integral_test(143));

    CHECK_FALSE(signed_integral_test(etl::uint8_t(42)));
    CHECK_FALSE(signed_integral_test(etl::uint16_t(143)));
    CHECK_FALSE(signed_integral_test(etl::uint32_t(143)));
    CHECK_FALSE(signed_integral_test(etl::uint64_t(143)));
    CHECK_FALSE(signed_integral_test(143U));
    CHECK_FALSE(signed_integral_test(143.0));
    CHECK_FALSE(signed_integral_test(143.0F));
    CHECK_FALSE(signed_integral_test(143.0L));

    CHECK(unsigned_integral_test(etl::uint8_t(42)));
    CHECK(unsigned_integral_test(etl::uint16_t(143)));
    CHECK(unsigned_integral_test(etl::uint32_t(143)));
    CHECK(unsigned_integral_test(etl::uint64_t(143)));
    CHECK(unsigned_integral_test(143U));

    CHECK_FALSE(unsigned_integral_test(etl::int8_t(42)));
    CHECK_FALSE(unsigned_integral_test(etl::int16_t(143)));
    CHECK_FALSE(unsigned_integral_test(etl::int32_t(143)));
    CHECK_FALSE(unsigned_integral_test(etl::int64_t(143)));
    CHECK_FALSE(unsigned_integral_test(143));
    CHECK_FALSE(unsigned_integral_test(143.0));
    CHECK_FALSE(unsigned_integral_test(143.0F));
    CHECK_FALSE(unsigned_integral_test(143.0L));

    CHECK(destructible_test(etl::uint8_t(42)));
    CHECK(destructible_test(etl::uint16_t(143)));
    CHECK(destructible_test(etl::uint32_t(143)));
    CHECK(destructible_test(etl::uint64_t(143)));
    CHECK(destructible_test(143U));

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
