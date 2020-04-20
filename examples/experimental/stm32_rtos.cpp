/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/
#include <stdio.h>

#include "taetl/experimental/hardware/stm32/stm32.hpp"
#include "taetl/experimental/rtos/rtos.hpp"

namespace rtos  = taetl::rtos;
namespace stm32 = taetl::hardware::stm32;

template <typename LoopType = rtos::forever>
struct idle_task
{
    auto run() -> void
    {
        auto loopControl = LoopType {};
        while (loopControl())
        {
            stm32::gpio_memory_layout memory {};
            auto& gpio_port = stm32::port::place_at(&memory);
            gpio_port.write(val(stm32::pin_number::pin_3),
                            stm32::pin_state::reset);
            rtos::delay(1);
        }
    }
};

auto foo(idle_task<rtos::once> task) -> void
{
    rtos::create_task(&task, "test", 15);
    task.run();
}

int main()
{
    foo({});
    return 0;
}
