// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#include "etl/new.hpp"

#define TETL_RTOS_USE_STUBS
#include "etl/experimental/hardware/stm32/gpio.hpp"  // for port, pin_number
#include "etl/experimental/rtos/delay.hpp"           // for delay, delay_until
#include "etl/experimental/rtos/task.hpp"            // for once, create_task

namespace rtos  = etl::experimental::rtos;
namespace stm32 = etl::experimental::hardware::stm32;

template <typename LoopType = rtos::forever>
struct example_task
{
  auto run() -> void
  {
    auto loopControl = LoopType {};
    while (loopControl())
    {
      stm32::gpio_memory_layout memory {};
      auto& gpioPort = stm32::port::place_at(&memory);
      gpioPort.write(stm32::pin_number::pin_13, stm32::pin_state::reset);
      gpioPort.toggle_pin(stm32::pin_number::pin_13);

      rtos::yield_task();
      rtos::delay(1);
      rtos::delay_until(1, 1);
    }

    rtos::delete_task(nullptr);
  }
};

static example_task<rtos::once> task {};

auto main() -> int
{
  rtos::create_task(task, "test", 255);
  rtos::start_scheduler();

  // Run would normally be called by rtos::start_scheduler(). Only used for
  // stubs.
  task.run();
  return 0;
}
