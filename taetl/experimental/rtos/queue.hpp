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

#ifndef TAETL_RTOS_QUEUE_HPP
#define TAETL_RTOS_QUEUE_HPP

#include "taetl/definitions.hpp"
#include "taetl/warning.hpp"

#include "taetl/experimental/rtos/stubs.hpp"
#if defined(TAETL_RTOS_USE_STUBS)
#endif

namespace taetl
{
namespace rtos
{
template <typename ValueType, taetl::uint32_t Size>
class queue
{
public:
    using value_type = ValueType;
    using size_type  = taetl::uint32_t;

    queue() : handle_([]() { return xQueueCreate(Size, sizeof(ValueType)); }())
    {
    }

    queue(queue&&)      = delete;
    queue(queue const&) = delete;
    auto operator=(queue &&) -> queue& = delete;
    auto operator=(queue const&) -> queue& = delete;

    ~queue()
    {
        if (handle_ != nullptr) { vQueueDelete(handle_); }
    }

    auto capacity() const -> size_type { return Size; }

    auto send(ValueType const& data, TickType_t ticksToWait = 0) const -> bool
    {
        auto const rawData = static_cast<const void*>(&data);
        auto const success = xQueueSend(handle_, rawData, ticksToWait);
        return static_cast<bool>(success);
    }

    auto receive(ValueType& data, TickType_t ticksToWait = 0) const -> bool
    {
        auto const rawData = static_cast<void*>(&data);
        auto const success = xQueueReceive(handle_, rawData, ticksToWait);
        return static_cast<bool>(success);
    }

private:
    QueueHandle_t handle_ = nullptr;
};
}  // namespace rtos
}  // namespace taetl

#endif  // TAETL_RTOS_QUEUE_HPP
