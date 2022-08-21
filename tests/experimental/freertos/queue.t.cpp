/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#define TETL_FREERTOS_USE_STUBS
#include "etl/experimental/freertos/queue.hpp"

#include "testing/testing.hpp"

namespace rtos = etl::experimental::freertos;

static auto test_all() -> bool
{
    {
        rtos::queue<float, 100> q1 {};
    }
    {
        rtos::queue<float, 1> q1 {};
        assert((q1.capacity() == 1));
        rtos::queue<float, 32> q2 {};
        assert((q2.capacity() == 32));
        rtos::queue<float, 128> q3 {};
        assert((q3.capacity() == 128));
    }
    {
        rtos::queue<float, 1> q1 {};
        // stub always returns false
        assert((q1.send(1, 0) == false));
    }

    {
        rtos::queue<int, 1> q1 {};
        // stub always returns false
        auto i = int { 0 };
        assert((q1.receive(i, 0) == false));
    }
    {
        rtos::queue<int, 1> q1 {};
        // stub always returns false
        auto [success, value] = q1.receive(0);
        assert((success == false));
        assert((value == 0));
    }
    {
        rtos::queue<int, 1> q1 {};
        assert((q1.reset() == true));
    }
    {
        rtos::queue<int, 1> q1 {};
        // stub always returns 0
        assert((q1.messages_waiting() == 0));
    }

    return true;
}

auto main() -> int
{
    assert(test_all());
    return 0;
}
