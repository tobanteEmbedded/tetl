// SPDX-License-Identifier: BSL-1.0

#define TETL_FREERTOS_USE_STUBS
#include <etl/experimental/freertos/stream_buffer.hpp>

#include "testing/testing.hpp"

namespace rtos = etl::experimental::freertos;
namespace net  = etl::experimental::net;

static auto test_all() -> bool
{
    auto sb = rtos::stream_buffer{128, 1};
    CHECK(sb.empty() == false);
    CHECK(sb.full() == false);
    CHECK(sb.bytes_available() == 0);
    CHECK(sb.space_available() == 0);

    auto read = etl::array<unsigned char, 16>{};
    CHECK(sb.read(net::make_buffer(read), 0) == 0);
    CHECK(sb.read_from_isr(net::make_buffer(read), nullptr) == 0);

    auto const write = etl::array<unsigned char, 16>{};
    CHECK(sb.write(net::make_buffer(write), 0) == 0);
    CHECK(sb.write_from_isr(net::make_buffer(write), nullptr) == 0);

    return true;
}

auto main() -> int
{
    CHECK(test_all());
    return 0;
}
