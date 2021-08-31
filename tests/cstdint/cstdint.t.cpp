/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/cstdint.hpp"

#include "testing.hpp"

constexpr auto test() -> bool
{
    assert(sizeof(etl::int8_t) == 1);
    assert(sizeof(etl::int16_t) == 2);
    assert(sizeof(etl::int32_t) == 4);
    assert(sizeof(etl::int64_t) == 8);
    assert(sizeof(etl::uint8_t) == 1);
    assert(sizeof(etl::uint16_t) == 2);
    assert(sizeof(etl::uint32_t) == 4);
    assert(sizeof(etl::uint64_t) == 8);
    return true;
}

auto main() -> int
{
    assert(test());
    static_assert(test());
    return 0;
}