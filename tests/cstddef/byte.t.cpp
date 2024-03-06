// SPDX-License-Identifier: BSL-1.0

#include <etl/cstddef.hpp>

#include <etl/cstdint.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    {
        auto const b = etl::byte {42};
        assert((etl::to_integer<T>(b) == T {42}));
    }

    {
        auto b = etl::byte {1};
        b <<= 1;
        assert((etl::to_integer<T>(b) == T {2}));
    }

    {
        auto b = etl::byte {1};
        b <<= 2;
        assert((etl::to_integer<T>(b) == T {4}));
    }

    {
        auto b = etl::byte {1};
        b <<= 3;
        assert((etl::to_integer<T>(b) == T {8}));
    }

    {
        auto b = etl::byte {2};
        b >>= 1;
        assert((etl::to_integer<T>(b) == T {1}));
    }

    {
        auto const b = etl::byte {1};

        {
            auto const c = b << 1;
            assert((etl::to_integer<int>(c) == 2));
        }

        {
            auto const c = b << 2;
            assert((etl::to_integer<int>(c) == 4));
        }

        {
            auto const c = b << 3;
            assert((etl::to_integer<int>(c) == 8));
        }
    }

    {
        auto const b = etl::byte {8};

        {
            auto const c = b >> 0;
            assert((etl::to_integer<int>(c) == 8));
        }

        {
            auto const c = b >> 1;
            assert((etl::to_integer<int>(c) == 4));
        }

        {
            auto const c = b >> 2;
            assert((etl::to_integer<int>(c) == 2));
        }

        {
            auto const c = b >> 3;
            assert((etl::to_integer<int>(c) == 1));
        }
    }

    {
        assert((etl::to_integer<int>(etl::byte {1} | etl::byte {0}) == 1));
        assert((etl::to_integer<int>(etl::byte {1} | etl::byte {1}) == 1));
        assert((etl::to_integer<int>(etl::byte {2} | etl::byte {1}) == 3));
    }

    {
        auto b1 = etl::byte {1};
        b1 |= etl::byte {0};
        assert((etl::to_integer<int>(b1) == 1));
    }

    {
        assert((etl::to_integer<int>(etl::byte {1} & etl::byte {0}) == 0));
        assert((etl::to_integer<int>(etl::byte {1} & etl::byte {1}) == 1));
        assert((etl::to_integer<int>(etl::byte {2} & etl::byte {1}) == 0));
    }

    {
        auto b1 = etl::byte {1};
        b1 &= etl::byte {1};
        assert((etl::to_integer<int>(b1) == 1));
    }

    {
        assert((etl::to_integer<int>(etl::byte {1} ^ etl::byte {0}) == 1));
        assert((etl::to_integer<int>(etl::byte {1} ^ etl::byte {1}) == 0));
        assert((etl::to_integer<int>(etl::byte {2} ^ etl::byte {1}) == 3));
    }

    {
        auto b1 = etl::byte {2};
        b1 ^= etl::byte {1};
        assert((etl::to_integer<int>(b1) == 3));
    }

    return true;
}

constexpr auto test_all() -> bool
{
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
