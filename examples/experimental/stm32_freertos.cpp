// SPDX-License-Identifier: BSL-1.0

#include "etl/new.hpp"

#define TETL_FREERTOS_USE_STUBS
#include "etl/experimental/freertos/task.hpp"       // for once, create_task
#include "etl/experimental/hardware/stm32/gpio.hpp" // for port, pin_number

namespace rtos  = etl::experimental::freertos;
namespace stm32 = etl::experimental::hardware::stm32;

template <typename LoopType = rtos::forever>
struct example_task {
    auto run() -> void
    {
        auto loopControl = LoopType {};
        while (loopControl()) {
            stm32::gpio_memory_layout memory {};
            auto& gpioPort = stm32::port::place_at(&memory);
            gpioPort.write(stm32::pin_number::pin_13, stm32::pin_state::reset);
            gpioPort.toggle_pin(stm32::pin_number::pin_13);

            rtos::this_task::yield();

            rtos::this_task::sleep_for(1);

            auto lastWake = etl::uint32_t {0};
            rtos::this_task::sleep_until(lastWake, 1);
        }

        rtos::delete_task(nullptr);
    }
};

namespace {
example_task<rtos::once> task {};
}

auto main() -> int
{
    rtos::create_task(task, "test", 255);
    rtos::start_scheduler();

    // Run would normally be called by rtos::start_scheduler(). Only used for
    // stubs.
    task.run();
    return 0;
}
