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

#ifndef TETL_FREERTOS_QUEUE_HPP
#define TETL_FREERTOS_QUEUE_HPP

#include "etl/version.hpp"

#include "etl/cstdint.hpp"
#include "etl/utility.hpp"
#include "etl/warning.hpp"

#if defined(TETL_FREERTOS_USE_STUBS)
#include "etl/experimental/freertos/stubs.hpp"
#endif

namespace etl::experimental::freertos {

/// \brief Wrapper around a FreeRTOS queue.
///
/// https://www.freertos.org/Embedded-RTOS-Queues.html
///
/// \tparam T The type that's being stored inside the queue.
/// \tparam Size The maximum capacity of the queue.
template <typename T, etl::uint32_t Size>
struct queue {
    using value_type = T;
    using size_type  = etl::uint32_t;

    /// \brief Creates a new queue. RAM is automatically allocated from the
    /// FreeRTOS heap.
    ///
    /// https://www.freertos.org/a00116.html
    queue();

    /// \brief Delete a queue - freeing all the memory allocated for storing of
    /// items placed on the queue.
    ///
    /// https://www.freertos.org/a00018.html#vQueueDelete
    ~queue();

    queue(queue const&) = delete;
    auto operator=(queue const&) -> queue& = delete;

    queue(queue&&) = delete;
    auto operator=(queue &&) -> queue& = delete;

    /// Returns the capacity of the internal buffer
    [[nodiscard]] auto capacity() const -> size_type;

    /// Push an element on to the queue.
    [[nodiscard]] auto send(T const& data, TickType_t ticksToWait = 0) const
        -> bool;

    /// Pop an element of the queue.
    auto receive(T& data, TickType_t ticksToWait = 0) const -> bool;

    /// Pop an element of the queue.
    [[nodiscard]] auto receive(TickType_t ticksToWait = 0) const
        -> pair<bool, T>;

    [[nodiscard]] auto reset() const -> bool;
    [[nodiscard]] auto messages_waiting() const -> etl::uint32_t;

private:
    QueueHandle_t handle_ = nullptr;
};

template <typename T, etl::uint32_t Size>
inline queue<T, Size>::queue()
    : handle_ { []() { return xQueueCreate(Size, sizeof(T)); }() }
{
}

template <typename T, etl::uint32_t Size>
inline queue<T, Size>::~queue()
{
    if (handle_ != nullptr) { vQueueDelete(handle_); }
}

template <typename T, etl::uint32_t Size>
inline auto queue<T, Size>::capacity() const -> size_type
{
    return Size;
}

template <typename T, etl::uint32_t Size>
inline auto queue<T, Size>::send(T const& data, TickType_t ticksToWait) const
    -> bool
{
    const auto* const rawData = static_cast<const void*>(&data);
    auto const success        = xQueueSend(handle_, rawData, ticksToWait);
    return static_cast<bool>(success);
}

template <typename T, etl::uint32_t Size>
inline auto queue<T, Size>::receive(T& data, TickType_t ticksToWait) const
    -> bool
{
    auto* const rawData = static_cast<void*>(&data);
    auto const success  = xQueueReceive(handle_, rawData, ticksToWait);
    return static_cast<bool>(success);
}

template <typename T, etl::uint32_t Size>
inline auto queue<T, Size>::receive(TickType_t ticksToWait) const
    -> pair<bool, T>
{
    auto value          = T {};
    auto* const rawData = static_cast<void*>(&value);
    auto const success  = xQueueReceive(handle_, rawData, ticksToWait);
    return { static_cast<bool>(success), value };
}

template <typename T, etl::uint32_t Size>
inline auto queue<T, Size>::reset() const -> bool
{
    auto const result = xQueueReset(handle_);
    return static_cast<bool>(result);
}

template <typename T, etl::uint32_t Size>
inline auto queue<T, Size>::messages_waiting() const -> etl::uint32_t
{
    auto const result = uxQueueMessagesWaiting(handle_);
    return static_cast<etl::uint32_t>(result);
}
} // namespace etl::experimental::freertos

#endif // TETL_FREERTOS_QUEUE_HPP
