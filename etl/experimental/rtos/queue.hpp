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

#ifndef TETL_RTOS_QUEUE_HPP
#define TETL_RTOS_QUEUE_HPP

#include "etl/version.hpp"

#include "etl/cstdint.hpp"
#include "etl/utility.hpp"
#include "etl/warning.hpp"

#if defined(TETL_RTOS_USE_STUBS)
#include "etl/experimental/rtos/stubs.hpp"
#endif

namespace etl::experimental::rtos
{
/// Wrapper around a FreeRTOS queue.
/// \tparam ValueType The type that's being stored inside the queue.
/// \tparam Size The maximum capacity of the queue.
template <typename ValueType, etl::uint32_t Size>
class queue
{
  public:
  /// The type that's being stored inside the queue
  using value_type = ValueType;
  /// The integer type used for the size
  using size_type = etl::uint32_t;

  /// Creates a new queue
  queue()
      : handle_([]() { return xQueueCreate(Size, sizeof(ValueType)); }()) { }

  queue(queue&&)      = delete;
  queue(queue const&) = delete;
  auto operator=(queue&&) -> queue& = delete;
  auto operator=(queue const&) -> queue& = delete;

  ~queue()
  {
    if (handle_ != nullptr) { vQueueDelete(handle_); }
  }

  /// Returns the capacity of the internal buffer
  [[nodiscard]] auto capacity() const -> size_type { return Size; }

  /// Push an element on to the queue.
  [[nodiscard]] auto send(ValueType const& data,
                          TickType_t ticksToWait = 0) const -> bool
  {
    const auto* const rawData = static_cast<const void*>(&data);
    auto const success        = xQueueSend(handle_, rawData, ticksToWait);
    return static_cast<bool>(success);
  }

  /// Pop an element of the queue.
  auto receive(ValueType& data, TickType_t ticksToWait = 0) const -> bool
  {
    auto* const rawData = static_cast<void*>(&data);
    auto const success  = xQueueReceive(handle_, rawData, ticksToWait);
    return static_cast<bool>(success);
  }

  /// Pop an element of the queue.
  [[nodiscard]] auto receive(TickType_t ticksToWait = 0) const
    -> pair<bool, ValueType>
  {
    auto value          = ValueType {};
    auto* const rawData = static_cast<void*>(&value);
    auto const success  = xQueueReceive(handle_, rawData, ticksToWait);
    return {static_cast<bool>(success), value};
  }

  [[nodiscard]] auto reset() const -> bool
  {
    auto const result = xQueueReset(handle_);
    return static_cast<bool>(result);
  }

  [[nodiscard]] auto messages_waiting() const -> etl::uint32_t
  {
    auto const result = uxQueueMessagesWaiting(handle_);
    return static_cast<etl::uint32_t>(result);
  }

  private:
  QueueHandle_t handle_ = nullptr;
};

}  // namespace etl::experimental::rtos

#endif  // TETL_RTOS_QUEUE_HPP
