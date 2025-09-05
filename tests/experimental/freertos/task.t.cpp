// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/experimental/freertos/task.hpp>
#endif

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
