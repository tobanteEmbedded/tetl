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

#ifndef TETL_FREERTOS_STREAM_BUFFER_HPP
#define TETL_FREERTOS_STREAM_BUFFER_HPP

#include "etl/version.hpp"

#include "etl/cstdint.hpp"
#include "etl/warning.hpp"

#include "etl/experimental/net/buffer.hpp"

#if defined(TETL_FREERTOS_USE_STUBS)
#include "etl/experimental/freertos/stubs.hpp"
#endif

namespace etl::experimental::freertos {

/// \brief Stream buffers are an RTOS task to RTOS task, and interrupt to task
/// communication primitives. Unlike most other FreeRTOS communications
/// primitives, they are optimised for single reader single writer scenarios,
/// such as passing data from an interrupt service routine to a task, or from
/// one microcontroller core to another on dual core CPUs. Data is passed by
/// copy - the data is copied into the buffer by the sender and out of the
/// buffer by the read.
///
/// https://www.freertos.org/RTOS-stream-buffer-API.html
/// https://www.freertos.org/RTOS-stream-message-buffers.html
///
/// \ingroup StreamBuffer
struct stream_buffer {
    using size_type = etl::size_t;

    /// \brief Creates a new stream buffer using dynamically allocated memory.
    ///
    /// https://www.freertos.org/xStreamBufferCreate.html
    stream_buffer(size_type size, size_type triggerLevel) noexcept;

    /// \brief Deletes a stream buffer, then the allocated memory is freed.
    ///
    /// https://www.freertos.org/vStreamBufferDelete.html
    ~stream_buffer() noexcept;

    stream_buffer(stream_buffer const& other) = delete;
    auto operator=(stream_buffer const& other) -> stream_buffer& = delete;

    stream_buffer(stream_buffer&& other) = delete;
    auto operator=(stream_buffer&& other) -> stream_buffer& = delete;

    /// \brief Sends bytes to a stream buffer. The bytes are copied into the
    /// stream buffer.
    ///
    /// https://www.freertos.org/xStreamBufferSend.html
    auto write(net::const_buffer data, TickType_t ticks) -> size_type;

    /// \brief Interrupt safe version of the API function that sends a stream of
    /// bytes to the stream buffer.
    ///
    /// https://www.freertos.org/xStreamBufferSendFromISR.html
    auto write_from_isr(net::const_buffer data, BaseType_t* prio) -> size_type;

    /// \brief Receives bytes from a stream buffer.
    ///
    /// https://www.freertos.org/xStreamBufferReceive.html
    auto read(net::mutable_buffer data, TickType_t ticks) -> size_type;

    /// \brief Receives bytes from a stream buffer.
    ///
    /// https://www.freertos.org/xStreamBufferReceiveFromISR.html
    auto read_from_isr(net::mutable_buffer data, BaseType_t* prio) -> size_type;

    /// \brief Queries a stream buffer to see if it is empty. A stream buffer is
    /// empty if it does not contain any data.
    ///
    /// https://www.freertos.org/xStreamBufferIsEmpty.html
    [[nodiscard]] auto empty() const noexcept -> bool;

    /// \brief Queries a stream buffer to see if it is full. A stream buffer is
    /// full if it does not have any free space, and therefore cannot accept any
    /// more data.
    ///
    /// https://www.freertos.org/xStreamBufferIsFull.html
    [[nodiscard]] auto full() const noexcept -> bool;

    /// \brief Queries a stream buffer to see how much data it contains, which
    /// is equal to the number of bytes that can be read from the stream buffer
    /// before the stream buffer would be empty.
    ///
    /// https://www.freertos.org/xStreamBufferBytesAvailable.html
    [[nodiscard]] auto bytes_available() const noexcept -> size_type;

    /// \brief Queries a stream buffer to see how much free space it contains,
    /// which is equal to the amount of data that can be sent to the stream
    /// buffer before it is full.
    ///
    /// https://www.freertos.org/xStreamBufferSpacesAvailable.html
    [[nodiscard]] auto space_available() const noexcept -> size_type;

    /// \brief Resets a stream buffer to its initial, empty, state. Any data
    /// that was in the stream buffer is discarded. A stream buffer can only be
    /// reset if there are no tasks blocked waiting to either send to or receive
    /// from the stream buffer.
    ///
    /// https://www.freertos.org/xStreamBufferReset.html
    auto reset() noexcept -> void;

    /// \brief A stream buffer's trigger level is the number of bytes that must
    /// be in the stream buffer before a task that is blocked on the stream
    /// buffer to wait for data is moved out of the blocked state.
    ///
    /// \details For example, if a task is blocked on a read of an empty stream
    /// buffer that has a trigger level of 1 then the task will be unblocked
    /// when a single byte is written to the buffer or the task's block time
    /// expires. As another example, if a task is blocked on a read of an empty
    /// stream buffer that has a trigger level of 10 then the task will not be
    /// unblocked until the stream buffer contains at least 10 bytes or the
    /// task's block time expires. If a reading task's block time expires before
    /// the trigger level is reached then the task will still receive however
    /// many bytes are actually available. Setting a trigger level of 0 will
    /// result in a trigger level of 1 being used. It is not valid to specify a
    /// trigger level that is greater than the buffer size.
    ///
    /// https://www.freertos.org/xStreamBufferSetTriggerLevel.html
    auto trigger_level(size_type triggerLevel) noexcept -> void;

    /// \brief Returns the native FreeRTOS handle to the stream_buffer
    [[nodiscard]] auto native_handle() const noexcept -> StreamBufferHandle_t;

private:
    StreamBufferHandle_t handle_;
};

inline stream_buffer::stream_buffer(size_t size, size_t triggerLevel) noexcept
    : handle_ { xStreamBufferCreate(size, triggerLevel) }
{
}

inline stream_buffer::~stream_buffer() noexcept
{
    vStreamBufferDelete(handle_);
}

inline auto stream_buffer::write(net::const_buffer data, TickType_t ticks)
    -> size_t
{
    return xStreamBufferSend(handle_, data.data(), data.size(), ticks);
}

inline auto stream_buffer::write_from_isr(
    net::const_buffer data, BaseType_t* prio) -> size_t
{
    return xStreamBufferSendFromISR(handle_, data.data(), data.size(), prio);
}

inline auto stream_buffer::read(net::mutable_buffer data, TickType_t ticks)
    -> size_t
{
    return xStreamBufferReceive(handle_, data.data(), data.size(), ticks);
}

inline auto stream_buffer::read_from_isr(
    net::mutable_buffer data, BaseType_t* prio) -> size_t
{
    return xStreamBufferReceiveFromISR(handle_, data.data(), data.size(), prio);
}

inline auto stream_buffer::empty() const noexcept -> bool
{
    return static_cast<bool>(xStreamBufferIsEmpty(handle_));
}

inline auto stream_buffer::full() const noexcept -> bool
{
    return static_cast<bool>(xStreamBufferIsFull(handle_));
}

inline auto stream_buffer::bytes_available() const noexcept -> size_type
{
    return xStreamBufferBytesAvailable(handle_);
}

inline auto stream_buffer::space_available() const noexcept -> size_type
{
    return xStreamBufferSpacesAvailable(handle_);
}

inline auto stream_buffer::reset() noexcept -> void
{
    xStreamBufferReset(handle_);
}

inline auto stream_buffer::trigger_level(size_type triggerLevel) noexcept
    -> void
{
    xStreamBufferSetTriggerLevel(handle_, triggerLevel);
}

inline auto stream_buffer::native_handle() const noexcept
    -> StreamBufferHandle_t
{
    return handle_;
}

} // namespace etl::experimental::freertos

#endif // TETL_FREERTOS_STREAM_BUFFER_HPP
