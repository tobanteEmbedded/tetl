// SPDX-License-Identifier: BSL-1.0

#define TETL_FREERTOS_USE_STUBS
#include <etl/experimental/freertos/task.hpp>

#include "testing/testing.hpp"

namespace rtos = etl::experimental::freertos;

template <typename LoopType = rtos::once>
struct SomeTask {
    auto run() -> void
    {
        auto loopControl = LoopType{};
        while (loopControl()) {
            rtos::this_task::yield();
        }

        rtos::delete_task(nullptr);
    }
};

static auto test_all() -> bool
{

    auto task = SomeTask<rtos::once>{};

    rtos::create_task(task, "test", 255);
    rtos::start_scheduler();

    // Run would normally be called by rtos::start_scheduler(). Only used
    // for stubs.
    rtos::rtos_task<SomeTask<rtos::once>>(static_cast<void*>(&task));

    return true;
}

auto main() -> int
{
    CHECK(test_all());
    return 0;
}
