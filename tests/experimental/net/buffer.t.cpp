// SPDX-License-Identifier: BSL-1.0

#include <etl/experimental/net/buffer.hpp>         // for make_buffer
#include <etl/experimental/net/buffer_const.hpp>   // for const_buffer, ope...
#include <etl/experimental/net/buffer_mutable.hpp> // for mutable_buffer

#include <etl/array.hpp> // for array

#include "testing/testing.hpp"

static auto test_all() -> bool
{
    {
        auto const buffer = etl::experimental::net::mutable_buffer{};
        CHECK(buffer.data() == nullptr);
        CHECK(buffer.size() == 0);
    }
    {
        auto mem = etl::array<char, 32>{};
        auto buf = etl::experimental::net::make_buffer(mem.data(), mem.size());
        CHECK(mem.data() == buf.data());
        CHECK(mem.size() == buf.size());
    }
    {
        auto mem = etl::array<char, 32>{};
        auto buf = etl::experimental::net::make_buffer(mem.data(), mem.size());
        buf += 4;
        CHECK(mem.data() != buf.data());
    }
    {
        auto mem = etl::array<char, 32>{};
        auto buf = etl::experimental::net::make_buffer(mem.data(), mem.size());

        {
            auto newBuf = buf + 4;
            CHECK(newBuf.size() == buf.size() - 4);
        }

        {
            auto newBuf = 8 + buf;
            CHECK(newBuf.size() == buf.size() - 8);
        }
    }
    {
        auto const buf = etl::experimental::net::const_buffer{};
        CHECK(buf.data() == nullptr);
        CHECK(buf.size() == 0);
    }
    {
        auto const mem = etl::array<char, 32>{};
        auto buf       = etl::experimental::net::make_buffer(mem.data(), mem.size());
        CHECK(mem.data() == buf.data());
        CHECK(mem.size() == buf.size());
    }
    {
        auto const mem = etl::array<char, 32>{};
        auto buf       = etl::experimental::net::make_buffer(mem.data(), mem.size());
        buf += 4;
        CHECK(mem.data() != buf.data());
        CHECK(mem.size() - 4 == buf.size());
    }

    {
        auto const mem = etl::array<char, 32>{};
        auto buf       = etl::experimental::net::make_buffer(mem.data(), mem.size());

        auto newBuf1 = buf + 4;
        CHECK(newBuf1.size() == buf.size() - 4);

        auto newBuf2 = 8 + buf;
        CHECK(newBuf2.size() == buf.size() - 8);
    }

    return true;
}

auto main() -> int
{
    CHECK(test_all());
    return 0;
}
