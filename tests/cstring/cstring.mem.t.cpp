// SPDX-License-Identifier: BSL-1.0

#include <etl/cstring.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/iterator.hpp>

#include "testing/testing.hpp"

static auto test() -> bool
{
    // memcpy
    {
        auto source = etl::array<etl::uint8_t, 2>{};
        source[0]   = 1;
        source[1]   = 2;
        CHECK(source[0] == 1);
        CHECK(source[1] == 2);

        auto destination = etl::array<etl::uint8_t, 2>{};
        CHECK(destination[0] == 0);
        CHECK(destination[1] == 0);

        etl::memcpy(destination.data(), source.data(), source.size());
        CHECK(source[0] == 1);
        CHECK(source[1] == 2);
        CHECK(destination[0] == 1);
        CHECK(destination[1] == 2);
    }

    // memset
    {
        auto buffer = etl::array<etl::uint8_t, 2>{};
        CHECK(buffer[0] == 0);
        CHECK(buffer[1] == 0);

        etl::memset(buffer.data(), 1, buffer.size());
        CHECK(buffer[0] == 1);
        CHECK(buffer[1] == 1);
    }

    // memchr: cppreference.com example
    {
        auto buffer = etl::array<char, 8>{'a', '\0', 'a', 'A', 'a', 'a', 'A', 'a'};
        auto* pos   = static_cast<char*>(etl::memchr(buffer.data(), 'A', buffer.size()));
        CHECK(*pos == 'A');
        CHECK(pos == etl::next(buffer.data(), 3));
        CHECK(etl::memchr(buffer.data(), 'B', buffer.size()) == nullptr);

        auto const& cbuffer = buffer;
        auto const* cpos    = static_cast<char const*>(etl::memchr(cbuffer.data(), 'A', cbuffer.size()));
        CHECK(*cpos == 'A');
        CHECK(cpos == etl::next(cbuffer.data(), 3));
        CHECK(etl::memchr(cbuffer.data(), 'B', cbuffer.size()) == nullptr);
    }

    return true;
}

auto main() -> int
{
    CHECK(test());
    return 0;
}
