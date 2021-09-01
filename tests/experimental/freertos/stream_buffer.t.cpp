/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#define TETL_FREERTOS_USE_STUBS
#include "etl/experimental/freertos/stream_buffer.hpp"

#include "testing.hpp"

namespace rtos = etl::experimental::freertos;
namespace net  = etl::experimental::net;

auto test_all() -> bool
{
    auto sb = rtos::stream_buffer { 128, 1 };
    assert((sb.empty() == false));
    assert((sb.full() == false));
    assert((sb.bytes_available() == 0));
    assert((sb.space_available() == 0));

    auto read = etl::array<unsigned char, 16> {};
    assert((sb.read(net::make_buffer(read), 0) == 0));
    assert((sb.read_from_isr(net::make_buffer(read), nullptr) == 0));

    auto const write = etl::array<unsigned char, 16> {};
    assert((sb.write(net::make_buffer(write), 0) == 0));
    assert((sb.write_from_isr(net::make_buffer(write), nullptr) == 0));

    return true;
}

auto main() -> int
{
    assert(test_all());
    return 0;
}