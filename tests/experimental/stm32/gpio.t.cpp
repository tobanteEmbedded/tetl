// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/bitset.hpp>
    #include <etl/experimental/hardware/stm32/gpio.hpp>
#endif

using namespace etl::experimental::hardware;
using register_bits = etl::bitset<32>;

static auto test_all() -> bool
{
    auto memory          = stm32::gpio_memory_layout{};
    memory.bit_set_reset = 0x0;
    auto& gpio           = stm32::port::place_at(&memory);

    // When pin is set to high, sets bits in bit_set_reset upper word
    {
        gpio.write(stm32::pin_number::pin_1, stm32::pin_state::set);
        CHECK(register_bits(memory.bit_set_reset).test(1 + 16));

        gpio.write(stm32::pin_number::pin_3, stm32::pin_state::set);
        CHECK(register_bits(memory.bit_set_reset).test(3 + 16));

        gpio.write(stm32::pin_number::pin_15, stm32::pin_state::set);
        CHECK(register_bits(memory.bit_set_reset).test(15 + 16));
    }

    // When pin is set to low, sets bits in bit_set_reset lower word
    {
        gpio.write(stm32::pin_number::pin_1, stm32::pin_state::reset);
        CHECK(register_bits(memory.bit_set_reset).test(1));

        gpio.write(stm32::pin_number::pin_3, stm32::pin_state::reset);
        CHECK(register_bits(memory.bit_set_reset).test(3));

        gpio.write(stm32::pin_number::pin_15, stm32::pin_state::reset);
        CHECK(register_bits(memory.bit_set_reset).test(15));
    }

    // When pin is set to toggle, toggles the output data bits
    {
        memory.output_data = 0x0;
        // Using pin 1
        {
            auto const original = register_bits(memory.output_data).test(1);
            gpio.toggle_pin(stm32::pin_number::pin_1);
            auto const toggled = register_bits(memory.output_data).test(1);
            CHECK(original != toggled);
        }

        // Using pin 15
        {
            auto const original = register_bits(memory.output_data).test(15);
            gpio.toggle_pin(stm32::pin_number::pin_15);
            auto const toggled = register_bits(memory.output_data).test(15);
            CHECK(original != toggled);
        }
    }
    return true;
}

auto main() -> int
{
    CHECK(test_all());
    return 0;
}
