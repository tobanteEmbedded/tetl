/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#define TETL_FREERTOS_USE_STUBS
#include "etl/experimental/freertos/stream_buffer.hpp"

#include "catch2/catch_template_test_macros.hpp"

namespace rtos = etl::experimental::freertos;
namespace net  = etl::experimental::net;

TEST_CASE("experimental/freertos/stream_buffer: stubs", "[experimental][rtos]")
{
    auto sb = rtos::stream_buffer { 128, 1 };
    REQUIRE(sb.empty() == false);
    REQUIRE(sb.full() == false);
    REQUIRE(sb.bytes_available() == 0);
    REQUIRE(sb.space_available() == 0);

    auto read = etl::array<unsigned char, 16> {};
    REQUIRE(sb.read(net::make_buffer(read), 0) == 0);
    REQUIRE(sb.read_from_isr(net::make_buffer(read), nullptr) == 0);

    auto const write = etl::array<unsigned char, 16> {};
    REQUIRE(sb.write(net::make_buffer(write), 0) == 0);
    REQUIRE(sb.write_from_isr(net::make_buffer(write), nullptr) == 0);
}