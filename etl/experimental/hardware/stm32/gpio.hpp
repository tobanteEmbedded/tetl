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

#ifndef TAETL_HARDWARE_STM32_GPIO_HPP
#define TAETL_HARDWARE_STM32_GPIO_HPP

#include "etl/definitions.hpp"
#include "etl/warning.hpp"

namespace etl::hardware::stm32
{
enum class pin_number : etl::uint16_t
{
    pin_0 = 0,
    pin_1,
    pin_2,
    pin_3,
    pin_4,
    pin_5,
    pin_6,
    pin_7,
    pin_8,
    pin_9,
    pin_10,
    pin_11,
    pin_12,
    pin_13,
    pin_14,
    pin_15,
};

enum class pin_state : uint8_t
{
    reset = 0,
    set,
};

inline auto val(pin_number pin) -> etl::uint16_t
{
    return static_cast<etl::uint16_t>(pin);
}

struct gpio_memory_layout
{
    volatile etl::uint32_t control_low;
    volatile etl::uint32_t control_high;
    volatile etl::uint32_t input_data;
    volatile etl::uint32_t output_data;
    volatile etl::uint32_t bit_set_reset;
    volatile etl::uint32_t bit_set;
    volatile etl::uint32_t lock;
};

struct port
{
    explicit port()   = default;
    ~port()           = default;
    port(port&&)      = delete;
    port(port const&) = delete;
    auto operator=(port&&) -> port& = delete;
    auto operator=(port const&) -> port& = delete;

    [[nodiscard]] auto read(pin_number const pin) -> pin_state
    {
        ignore_unused(val(pin));
        return {};
    }

    void write(pin_number const pin, pin_state const state)
    {
        if (state == pin_state::reset)
        {
            memory.bit_set_reset = (1U << val(pin));
            return;
        }
        memory.bit_set_reset = (1U << (val(pin) + 16U));
    }

    void toggle_pin(pin_number const pin) { memory.output_data ^= (1U << val(pin)); }

    [[nodiscard]] static auto place_at(void* addr) -> port& { return *new (addr) port; }

private:
    gpio_memory_layout memory;
};
}  // namespace etl::hardware::stm32

#endif  // TAETL_HARDWARE_STM32_GPIO_HPP
