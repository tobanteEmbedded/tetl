/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "catch2/catch_template_test_macros.hpp"

#include "etl/experimental/hardware/stm32/gpio.hpp"

#include "etl/bitset.hpp"

using namespace etl::experimental::hardware;
using register_bits = etl::bitset<32>;

TEST_CASE("experimental/stm32: gpio", "[stm32][hardware][experimental]")
{
    auto memory          = stm32::gpio_memory_layout {};
    memory.bit_set_reset = 0x0;
    auto& gpio           = stm32::port::place_at(&memory);

    SECTION("When pin is set to high, sets bits in bit_set_reset upper word")
    {
        gpio.write(stm32::pin_number::pin_1, stm32::pin_state::set);
        REQUIRE(register_bits(memory.bit_set_reset).test(1 + 16));

        gpio.write(stm32::pin_number::pin_3, stm32::pin_state::set);
        REQUIRE(register_bits(memory.bit_set_reset).test(3 + 16));

        gpio.write(stm32::pin_number::pin_15, stm32::pin_state::set);
        REQUIRE(register_bits(memory.bit_set_reset).test(15 + 16));
    }

    SECTION("When pin is set to low, sets bits in bit_set_reset lower word")
    {
        gpio.write(stm32::pin_number::pin_1, stm32::pin_state::reset);
        REQUIRE(register_bits(memory.bit_set_reset).test(1));

        gpio.write(stm32::pin_number::pin_3, stm32::pin_state::reset);
        REQUIRE(register_bits(memory.bit_set_reset).test(3));

        gpio.write(stm32::pin_number::pin_15, stm32::pin_state::reset);
        REQUIRE(register_bits(memory.bit_set_reset).test(15));
    }

    SECTION("When pin is set to toggle, toggles the output data bits")
    {
        memory.output_data = 0x0;
        WHEN("Using pin 1")
        {
            auto const original = register_bits(memory.output_data).test(1);
            gpio.toggle_pin(stm32::pin_number::pin_1);
            auto const toggled = register_bits(memory.output_data).test(1);
            REQUIRE(original != toggled);
        }

        WHEN("Using pin 15")
        {
            auto const original = register_bits(memory.output_data).test(15);
            gpio.toggle_pin(stm32::pin_number::pin_15);
            auto const toggled = register_bits(memory.output_data).test(15);
            REQUIRE(original != toggled);
        }
    }
}