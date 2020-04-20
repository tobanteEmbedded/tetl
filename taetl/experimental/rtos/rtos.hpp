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

#ifndef TAETL_RTOS_RTOS_HPP
#define TAETL_RTOS_RTOS_HPP

#include "taetl/definitions.hpp"
#include "taetl/experimental/rtos/stubs.hpp"

namespace taetl
{
namespace rtos
{
inline auto delay(taetl::size_t) -> void {}

struct never
{
    [[nodiscard]] auto operator()() const -> bool { return false; }
};

struct forever
{
    [[nodiscard]] auto operator()() const -> bool { return true; }
};

template <taetl::size_t Count>
struct times
{
    taetl::size_t run_count = Count;
    [[nodiscard]] auto operator()() -> bool { return (run_count-- != 0); }
};

using once  = times<1>;
using twice = times<2>;

template <typename TaskType>
auto rtos_task(void* task) -> void
{
    static_cast<TaskType*>(task)->run();
};

template <typename TaskType>
auto create_task(TaskType* task, char const* const name, int stack) -> void
{
    xTaskCreate(rtos_task<TaskType>, name, stack, static_cast<void*>(task), 0,
                nullptr);
};

}  // namespace rtos
}  // namespace taetl

#endif  // TAETL_RTOS_RTOS_HPP
