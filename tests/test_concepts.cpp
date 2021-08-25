/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/concepts.hpp"

#include "etl/cstdint.hpp"

#include "catch2/catch_template_test_macros.hpp"

#if defined(__cpp_concepts) && TETL_CPP_STANDARD >= 20

namespace {
auto floating_point_test(etl::floating_point auto /*unused*/) { return true; }

auto floating_point_test(auto /*unused*/) { return false; }
} // namespace

TEST_CASE("concepts: floating_point", "[concepts]")
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
}

namespace {
auto integral_test(etl::integral auto /*unused*/) { return true; }

auto integral_test(auto /*unused*/) { return false; }
} // namespace

TEST_CASE("concepts: integral", "[concepts]")
{
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
}

namespace {
auto signed_integral_test(etl::signed_integral auto /*unused*/) { return true; }

auto signed_integral_test(auto /*unused*/) { return false; }
} // namespace

TEST_CASE("concepts: signed_integral", "[concepts]")
{
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
}

namespace {
auto unsigned_integral_test(etl::unsigned_integral auto /*unused*/)
{
    return true;
}

auto unsigned_integral_test(auto /*unused*/) { return false; }
} // namespace

TEST_CASE("concepts: unsigned_integral", "[concepts]")
{
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
}

namespace {
auto destructible_test(etl::destructible auto /*unused*/) { return true; }

auto destructible_test(auto /*unused*/) { return false; }
} // namespace

TEST_CASE("concepts: destructible", "[concepts]")
{
    CHECK(destructible_test(etl::uint8_t(42)));
    CHECK(destructible_test(etl::uint16_t(143)));
    CHECK(destructible_test(etl::uint32_t(143)));
    CHECK(destructible_test(etl::uint64_t(143)));
    CHECK(destructible_test(143U));
}

#endif
