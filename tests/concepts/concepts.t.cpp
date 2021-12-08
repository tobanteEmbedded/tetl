/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/concepts.hpp"

#include "etl/cstdint.hpp"

#include "testing/testing.hpp"

#if defined(__cpp_concepts)

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

constexpr auto test() -> bool
{
    assert(floating_point_test(143.0));
    assert(floating_point_test(143.0F));
    assert(floating_point_test(143.0L));

    assert(!floating_point_test(etl::int8_t(42)));
    assert(!floating_point_test(etl::uint8_t(42)));
    assert(!floating_point_test(etl::int16_t(143)));
    assert(!floating_point_test(etl::uint16_t(143)));
    assert(!floating_point_test(etl::int32_t(143)));
    assert(!floating_point_test(etl::uint32_t(143)));
    assert(!floating_point_test(etl::int64_t(143)));
    assert(!floating_point_test(etl::uint64_t(143)));
    assert(!floating_point_test(143));
    assert(!floating_point_test(143U));

    assert(integral_test(etl::int8_t(42)));
    assert(integral_test(etl::uint8_t(42)));
    assert(integral_test(etl::int16_t(143)));
    assert(integral_test(etl::uint16_t(143)));
    assert(integral_test(etl::int32_t(143)));
    assert(integral_test(etl::uint32_t(143)));
    assert(integral_test(etl::int64_t(143)));
    assert(integral_test(etl::uint64_t(143)));
    assert(integral_test(143));
    assert(integral_test(143U));

    assert(!integral_test(143.0));
    assert(!integral_test(143.0F));
    assert(!integral_test(143.0L));

    assert(signed_integral_test(etl::int8_t(42)));
    assert(signed_integral_test(etl::int16_t(143)));
    assert(signed_integral_test(etl::int32_t(143)));
    assert(signed_integral_test(etl::int64_t(143)));
    assert(signed_integral_test(143));

    assert(!signed_integral_test(etl::uint8_t(42)));
    assert(!signed_integral_test(etl::uint16_t(143)));
    assert(!signed_integral_test(etl::uint32_t(143)));
    assert(!signed_integral_test(etl::uint64_t(143)));
    assert(!signed_integral_test(143U));
    assert(!signed_integral_test(143.0));
    assert(!signed_integral_test(143.0F));
    assert(!signed_integral_test(143.0L));

    assert(unsigned_integral_test(etl::uint8_t(42)));
    assert(unsigned_integral_test(etl::uint16_t(143)));
    assert(unsigned_integral_test(etl::uint32_t(143)));
    assert(unsigned_integral_test(etl::uint64_t(143)));
    assert(unsigned_integral_test(143U));

    assert(!unsigned_integral_test(etl::int8_t(42)));
    assert(!unsigned_integral_test(etl::int16_t(143)));
    assert(!unsigned_integral_test(etl::int32_t(143)));
    assert(!unsigned_integral_test(etl::int64_t(143)));
    assert(!unsigned_integral_test(143));
    assert(!unsigned_integral_test(143.0));
    assert(!unsigned_integral_test(143.0F));
    assert(!unsigned_integral_test(143.0L));

    assert(destructible_test(etl::uint8_t(42)));
    assert(destructible_test(etl::uint16_t(143)));
    assert(destructible_test(etl::uint32_t(143)));
    assert(destructible_test(etl::uint64_t(143)));
    assert(destructible_test(143U));

    return true;
}

auto main() -> int
{
    assert(test());
    static_assert(test());
    return 0;
}

#else
auto main() -> int { return 0; }
#endif