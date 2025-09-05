// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FREERTOS_TASK_HPP
#define TETL_FREERTOS_TASK_HPP

#include <etl/version.hpp>

#include <etl/cstddef.hpp>
#include <etl/utility.hpp>

#if defined(TETL_FREERTOS_USE_STUBS)
    #include <etl/experimental/freertos/stubs.hpp>
#endif

namespace etl::experimental::freertos {
/// \brief Runs the task loop 0 times.
struct never {
    [[nodiscard]] auto operator()() const -> bool
    {
        return false;
    }
};

/// \brief Runs the task loop forever.
struct forever {
    [[nodiscard]] auto operator()() const -> bool
    {
        return true;
    }
};

/// \brief Runs the task loop Count times.
template <etl::size_t Count>
struct times {
    etl::size_t run_count = Count;

    [[nodiscard]] auto operator()() -> bool
    {
        return (run_count-- != 0);
    }
};

/// \brief Runs the task loop once.
using once = times<1>;

/// \brief Runs the task loop twice.
using twice = times<2>;

/// \brief Wrapper for an rtos task struct. Calls the run() member.
template <typename TaskType>
inline auto rtos_task(void* task) -> void
{
    static_cast<TaskType*>(task)->run();
}

/// \brief Create a rtos task. TaskType needs a `void run()` public method.
template <typename TaskType>
inline auto create_task(
    TaskType& task,
    char const* const name,
    uint16_t stack,
    UBaseType_t prio           = 0,
    TaskHandle_t* const handle = nullptr
) -> void
{
    xTaskCreate(rtos_task<TaskType>, name, stack, static_cast<void*>(&task), prio, handle);
}

/// \brief Delete a rtos task. If handle is nullptr, the current task will be
/// deleted.
inline auto delete_task(TaskHandle_t task) -> void
{
    vTaskDelete(task);
}

/// \brief Start the RTOS, this function will never return and will schedule the
/// tasks.
inline auto start_scheduler() -> void
{
    vTaskStartScheduler();
}

namespace this_task {
/// \brief Request a context switch to another task.
///
/// \details However, if there are no other tasks at a higher or equal
/// priority to the task that calls yield() then the RTOS scheduler will
/// simply select the task that called yield() to run again.
///
/// If configUSE_PREEMPTION is set to 1 then the RTOS scheduler will always
/// be running the highest priority task that is able to run, so calling
/// yield() will never result in a switch to a higher priority task.
///
/// https://www.freertos.org/a00020.html#taskYIELD
auto yield() -> void;

/// \brief Delay a task for a given number of ticks. The actual time that
/// the task remains blocked depends on the tick rate.
///
/// \details sleep_for() specifies a time at which the task wishes to
/// unblock relative to the time at which sleep_for() is called. For
/// example, specifying a block period of 100 ticks will cause the task to
/// unblock 100 ticks after sleep_for() is called. sleep_for() does not
/// therefore provide a good method of controlling the frequency of a
/// periodic task as the path taken through the code, as well as other task
/// and interrupt activity, will effect the frequency at which sleep_for()
/// gets called and therefore the time at which the task next executes. See
/// sleep_until() for an alternative API function designed to facilitate
/// fixed frequency execution. It does this by specifying an absolute time
/// (rather than a relative time) at which the calling task should unblock.
///
/// https://www.freertos.org/a00127.html
auto sleep_for(etl::uint32_t ticks) -> void;

/// \brief Delay a task until a specified time. This function can be used by
/// periodic tasks to ensure a constant execution frequency.
///
/// \details  This function differs from sleep_for() in one important
/// aspect: sleep_for() specifies a time at which the task wishes to
/// unblock relative to the time at which sleep_for() is called, whereas
/// sleep_until() specifies an absolute time at which the task wishes to
/// unblock. sleep_for() will cause a task to block for the specified
/// number of ticks from the time sleep_for() is called. It is therefore
/// difficult to use sleep_for() by itself to generate a fixed execution
/// frequency as the time between a task unblocking following a call to
/// sleep_for() and that task next calling sleep_for() may not be fixed
/// [the task may take a different path though the code between calls, or
/// may get interrupted or preempted a different number of times each time
/// it executes].
///
/// https://www.freertos.org/vtaskdelayuntil.html
auto sleep_until(etl::uint32_t& prev, etl::uint32_t increment) -> void;

inline auto yield() -> void
{
    taskYIELD();
}

inline auto sleep_for(etl::uint32_t ticks) -> void
{
    vTaskDelay(ticks);
}

inline auto sleep_until(etl::uint32_t& prev, etl::uint32_t increment) -> void
{
    vTaskDelayUntil(&prev, increment);
}
} // namespace this_task

} // namespace etl::experimental::freertos

#endif // TETL_FREERTOS_TASK_HPP
