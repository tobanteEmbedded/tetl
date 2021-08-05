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

#ifndef TETL_HARDWARE_STM32_INTERRUPT_HPP
#define TETL_HARDWARE_STM32_INTERRUPT_HPP

#include "etl/version.hpp"

#include "etl/array.hpp"
#include "etl/cstddef.hpp"

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

enum class isr_ids : size_t {
    nmi,
    hard_fault,
    sys_tick,
    max_id,
};

struct isr {
    using callback_t = void (*)();
    using vector_t
        = etl::array<callback_t, static_cast<size_t>(isr_ids::max_id)>;

    static auto call(vector_t const& callbacks, isr_ids id) noexcept -> void
    {
        callbacks[static_cast<size_t>(id)]();
    }

    static auto call_checked(vector_t const& callbacks, isr_ids id) noexcept
        -> void
    {
        if (callbacks[static_cast<size_t>(id)] != nullptr) {
            callbacks[static_cast<size_t>(id)]();
        }
    }
};
} // namespace etl::experimental::hardware::stm32

#endif // TETL_HARDWARE_STM32_INTERRUPT_HPP
