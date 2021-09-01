/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/cstddef.hpp"

#include "etl/cstdint.hpp"

#include "testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    {
        auto const b = etl::byte { 42 };
        assert((etl::to_integer<T>(b) == T { 42 }));
    }

    {
        auto b = etl::byte { 1 };
        b <<= 1;
        assert((etl::to_integer<T>(b) == T { 2 }));
    }

    {
        auto b = etl::byte { 1 };
        b <<= 2;
        assert((etl::to_integer<T>(b) == T { 4 }));
    }

    {
        auto b = etl::byte { 1 };
        b <<= 3;
        assert((etl::to_integer<T>(b) == T { 8 }));
    }

    {
        auto b = etl::byte { 2 };
        b >>= 1;
        assert((etl::to_integer<T>(b) == T { 1 }));
    }

    {
        auto b = etl::byte { 1 };
        assert((etl::to_integer<int>(b << 1) == 2));
        assert((etl::to_integer<int>(b << 2) == 4));
        assert((etl::to_integer<int>(b << 3) == 8));
    }

    {
        auto b = etl::byte { 8 };
        assert((etl::to_integer<int>(b >> 0) == 8));
        assert((etl::to_integer<int>(b >> 1) == 4));
        assert((etl::to_integer<int>(b >> 2) == 2));
        assert((etl::to_integer<int>(b >> 3) == 1));
    }

    {
        assert((etl::to_integer<int>(etl::byte { 1 } | etl::byte { 0 }) == 1));
        assert((etl::to_integer<int>(etl::byte { 1 } | etl::byte { 1 }) == 1));
        assert((etl::to_integer<int>(etl::byte { 2 } | etl::byte { 1 }) == 3));
    }

    {
        auto b1 = etl::byte { 1 };
        b1 |= etl::byte { 0 };
        assert((etl::to_integer<int>(b1) == 1));
    }

    {
        assert((etl::to_integer<int>(etl::byte { 1 } & etl::byte { 0 }) == 0));
        assert((etl::to_integer<int>(etl::byte { 1 } & etl::byte { 1 }) == 1));
        assert((etl::to_integer<int>(etl::byte { 2 } & etl::byte { 1 }) == 0));
    }

    {
        auto b1 = etl::byte { 1 };
        b1 &= etl::byte { 1 };
        assert((etl::to_integer<int>(b1) == 1));
    }

    {
        assert((etl::to_integer<int>(etl::byte { 1 } ^ etl::byte { 0 }) == 1));
        assert((etl::to_integer<int>(etl::byte { 1 } ^ etl::byte { 1 }) == 0));
        assert((etl::to_integer<int>(etl::byte { 2 } ^ etl::byte { 1 }) == 3));
    }

    {
        auto b1 = etl::byte { 2 };
        b1 ^= etl::byte { 1 };
        assert((etl::to_integer<int>(b1) == 3));
    }

    return true;
}

constexpr auto test_all() -> bool
{
    // Smaller types get promoted when used with va_list
    assert(test<etl::uint8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::uint64_t>());
    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}