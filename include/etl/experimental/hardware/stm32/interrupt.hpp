// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_HARDWARE_STM32_INTERRUPT_HPP
#define TETL_HARDWARE_STM32_INTERRUPT_HPP

#include <etl/version.hpp>

#include <etl/array.hpp>
#include <etl/cstddef.hpp>

namespace etl::experimental::hardware::stm32 {
// EXAMPLE
// extern isr::vector_t callbacks;

// static void dummy_handler() {
// }

// constexpr auto callbacks = isr::vector_t{
//     nullptr,
//     dummy_handler,
//     dummy_handler,
// };

// void NMI_Handler() { isr::call(callbacks, isr_ids::nmi); }
// void HardFault_Handler() { isr::call(callbacks, isr_ids::hard_fault); }
// void SysTick_Handler() { isr::call_checked(callbacks, isr_ids::sys_tick); }

enum struct isr_ids : size_t {
    nmi,
    hard_fault,
    sys_tick,
    max_id,
};

struct isr {
    using callback_t = void (*)();
    using vector_t   = etl::array<callback_t, static_cast<size_t>(isr_ids::max_id)>;

    static auto call(vector_t const& callbacks, isr_ids id) noexcept -> void
    {
        callbacks[static_cast<size_t>(id)]();
    }

    static auto call_checked(vector_t const& callbacks, isr_ids id) noexcept -> void
    {
        if (callbacks[static_cast<size_t>(id)] != nullptr) {
            callbacks[static_cast<size_t>(id)]();
        }
    }
};
} // namespace etl::experimental::hardware::stm32

#endif // TETL_HARDWARE_STM32_INTERRUPT_HPP
