// SPDX-License-Identifier: BSL-1.0

#include <etl/utility.hpp>

#include <etl/cstdint.hpp>
#include <etl/type_traits.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    {
        // mutable l-value
        auto t = T(0);
        auto u = T(1);
        ASSERT(not etl::is_const_v<decltype(etl::forward_like<decltype(t)>(u))>);
        ASSERT(etl::is_rvalue_reference_v<decltype(etl::forward_like<decltype(t)>(u))>);
    }

    return true;
}

constexpr auto test_all() -> bool
{
    ASSERT(test<etl::uint8_t>());
    ASSERT(test<etl::int8_t>());
    ASSERT(test<etl::uint16_t>());
    ASSERT(test<etl::int16_t>());
    ASSERT(test<etl::uint32_t>());
    ASSERT(test<etl::int32_t>());
    ASSERT(test<etl::uint64_t>());
    ASSERT(test<etl::int64_t>());
    return true;
}

auto main() -> int
{
    ASSERT(test_all());
    static_assert(test_all());
    return 0;
}
