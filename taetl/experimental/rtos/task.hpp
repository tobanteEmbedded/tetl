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

#ifndef TAETL_RTOS_TASK_HPP
#define TAETL_RTOS_TASK_HPP

#include "taetl/definitions.hpp"
#include "taetl/warning.hpp"

#if defined(TAETL_RTOS_USE_STUBS)
#include "taetl/experimental/rtos/stubs.hpp"
#endif

namespace taetl
{
namespace rtos
{
/**
 * @brief Runs the task loop 0 times.
 */
struct never
{
    [[nodiscard]] auto operator()() const -> bool { return false; }
};

/**
 * @brief Runs the task loop forever.
 */
struct forever
{
    [[nodiscard]] auto operator()() const -> bool { return true; }
};

/**
 * @brief Runs the task loop Count times.
 */
template <taetl::size_t Count>
struct times
{
    taetl::size_t run_count = Count;
    [[nodiscard]] auto operator()() -> bool { return (run_count-- != 0); }
};

/**
 * @brief Runs the task loop once.
 */
using once = times<1>;

/**
 * @brief Runs the task loop twice.
 */
using twice = times<2>;

/**
 * @brief Wrapper for an rtos task struct. Calls the run() member.
 */
template <typename TaskType>
inline auto rtos_task(void* task) -> void
{
    static_cast<TaskType*>(task)->run();
}

/**
 * @brief Create a rtos task. TaskType needs a `void run()` public method.
 */
template <typename TaskType>
inline auto create_task(TaskType& task, char const* const name, uint16_t stack,
                        UBaseType_t prio           = 0,
                        TaskHandle_t* const handle = nullptr) -> void
{
    xTaskCreate(rtos_task<TaskType>, name, stack, static_cast<void*>(&task),
                prio, handle);
}

/**
 * @brief Delete a rtos task. If handle is nullptr, the current task will be
 * deleted.
 */
inline auto delete_task(TaskHandle_t task) -> void { vTaskDelete(task); }

/**
 * @brief Start the RTOS, this function will never return and will schedule the
 * tasks.
 */
inline auto start_scheduler() -> void { vTaskStartScheduler(); }
}  // namespace rtos
}  // namespace taetl

#endif  // TAETL_RTOS_TASK_HPP
