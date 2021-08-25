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

#ifndef TETL_HARDWARE_STM32_GPIO_HPP
#define TETL_HARDWARE_STM32_GPIO_HPP

#include "etl/version.hpp"

#include "etl/cstdint.hpp"
#include "etl/new.hpp"
#include "etl/warning.hpp"

namespace etl::experimental::hardware::stm32 {
enum struct pin_number : etl::uint16_t {
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

enum struct pin_state : etl::uint8_t {
    reset = 0,
    set,
};

inline auto val(pin_number pin) -> etl::uint16_t
{
    return static_cast<etl::uint16_t>(pin);
}

struct gpio_memory_layout {
    etl::uint32_t volatile control_low;
    etl::uint32_t volatile control_high;
    etl::uint32_t volatile input_data;
    etl::uint32_t volatile output_data;
    etl::uint32_t volatile bit_set_reset;
    etl::uint32_t volatile bit_set;
    etl::uint32_t volatile lock;
};

struct port {
    ~port() = default;

    port(port const&) = delete;
    auto operator=(port const&) -> port& = delete;

    port(port&&) = delete;
    auto operator=(port&&) -> port& = delete;

    auto toggle_pin(pin_number pin) noexcept -> void;
    auto write(pin_number pin, pin_state state) noexcept -> void;
    [[nodiscard]] auto read(pin_number pin) noexcept -> pin_state;

    [[nodiscard]] static auto place_at(void* addr) -> port&;

private:
    explicit port() = default;

    gpio_memory_layout memory_;
};

inline auto port::read(pin_number const pin) noexcept -> pin_state
{
    etl::ignore_unused(this, pin);
    return {};
}

inline auto port::write(pin_number const pin, pin_state const state) noexcept
    -> void
{
    if (state == pin_state::reset) {
        memory_.bit_set_reset = (1U << val(pin));
        return;
    }
    memory_.bit_set_reset = (1U << (val(pin) + 16U));
}

inline auto port::toggle_pin(pin_number const pin) noexcept -> void
{
    memory_.output_data = memory_.output_data ^ (1U << val(pin));
}

inline auto port::place_at(void* addr) -> port& { return *new (addr) port; }

} // namespace etl::experimental::hardware::stm32

#endif // TETL_HARDWARE_STM32_GPIO_HPP
