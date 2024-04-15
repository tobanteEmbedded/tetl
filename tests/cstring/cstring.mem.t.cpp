// SPDX-License-Identifier: BSL-1.0

#include <etl/cstring.hpp>

#include <etl/array.hpp>
#include <etl/cstdint.hpp>
#include <etl/iterator.hpp>
#include <etl/string_view.hpp>

#include "testing/testing.hpp"

using namespace etl::string_view_literals;

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

    // memmove: no overlap
    {
        {
            auto src  = etl::array<char, 4>{'a', 'b', 'c', 'd'};
            auto dest = etl::array<char, 4>{};
            etl::memmove(dest.data(), src.data(), src.size());
            CHECK(etl::string_view{dest.data(), dest.size()} == "abcd"_sv);
        }
        {
            auto dest = etl::array<char, 4>{};
            auto src  = etl::array<char, 4>{'a', 'b', 'c', 'd'};
            etl::memmove(dest.data(), src.data(), src.size());
            CHECK(etl::string_view{dest.data(), dest.size()} == "abcd"_sv);
        }
    }

    // memmove: cppreference.com example
    {
        char str[] = "1234567890";
        etl::memmove(str + 4, str + 3, 3);
        CHECK(str == "1234456890"_sv);
    }

    return true;
}

auto main() -> int
{
    CHECK(test());
    return 0;
}
