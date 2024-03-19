// SPDX-License-Identifier: BSL-1.0

#define TETL_FREERTOS_USE_STUBS
#include <etl/experimental/freertos/queue.hpp>

#include "testing/testing.hpp"

namespace rtos = etl::experimental::freertos;

static auto test_all() -> bool
{
    {
        rtos::queue<float, 100> q1{};
    }
    {
        rtos::queue<float, 1> q1{};
        CHECK(q1.capacity() == 1);
        rtos::queue<float, 32> q2{};
        CHECK(q2.capacity() == 32);
        rtos::queue<float, 128> q3{};
        CHECK(q3.capacity() == 128);
    }
    {
        rtos::queue<float, 1> q1{};
        // stub always returns false
        CHECK(q1.send(1, 0) == false);
    }

    {
        rtos::queue<int, 1> q1{};
        // stub always returns false
        auto i = int{0};
        CHECK(q1.receive(i, 0) == false);
    }
    {
        rtos::queue<int, 1> q1{};
        // stub always returns false
        auto [success, value] = q1.receive(0);
        CHECK(success == false);
        CHECK(value == 0);
    }
    {
        rtos::queue<int, 1> q1{};
        CHECK(q1.reset() == true);
    }
    {
        rtos::queue<int, 1> q1{};
        // stub always returns 0
        CHECK(q1.messages_waiting() == 0);
    }

    return true;
}

auto main() -> int
{
    CHECK(test_all());
    return 0;
}
