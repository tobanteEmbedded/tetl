/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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

inline auto val(pin_number pin) -> etl::uint16_t { return static_cast<etl::uint16_t>(pin); }

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

inline auto port::write(pin_number const pin, pin_state const state) noexcept -> void
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
