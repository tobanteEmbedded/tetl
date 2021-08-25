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

#ifndef TETL_FREERTOS_STUBS_HPP
#define TETL_FREERTOS_STUBS_HPP

#include "etl/version.hpp"

#include "etl/cstddef.hpp"
#include "etl/cstdint.hpp"
#include "etl/warning.hpp"

// BASE
using BaseType_t             = long;
using UBaseType_t            = unsigned long;
using configSTACK_DEPTH_TYPE = etl::uint16_t;
#define pdFALSE (static_cast<BaseType_t>(0))
#define pdTRUE (static_cast<BaseType_t>(1))
#define pdPASS (pdTRUE)
#define pdFAIL (pdFALSE)
#define errQUEUE_EMPTY (static_cast<BaseType_t>(0))
#define errQUEUE_FULL (static_cast<BaseType_t>(0))

// TICK
using TickType_t = etl::uint32_t;

// SCHEDULER
inline auto vPortYield() -> void { }
#define portYIELD() vPortYield()
#define taskYIELD() portYIELD()

// TASK
struct tskTaskControlBlock;

using TaskHandle_t   = tskTaskControlBlock*;
using TaskFunction_t = void (*)(void*);

inline auto xTaskCreate(TaskFunction_t pvTaskCode, char const* const pcName,
    configSTACK_DEPTH_TYPE usStackDepth, void* const pvParameters,
    UBaseType_t uxPriority, TaskHandle_t* const pxCreatedTask) -> BaseType_t
{
    etl::ignore_unused(pvTaskCode, pcName, usStackDepth, pvParameters,
        uxPriority, pxCreatedTask);
    return pdFALSE;
}

inline auto vTaskDelete(TaskHandle_t xTask) -> void
{
    etl::ignore_unused(xTask);
}

inline auto vTaskStartScheduler() -> void { }

inline auto vTaskDelay(TickType_t const xTicksToDelay) -> void
{
    etl::ignore_unused(xTicksToDelay);
}

inline auto vTaskDelayUntil(TickType_t* const pxPreviousWakeTime,
    const TickType_t xTimeIncrement) -> void
{
    etl::ignore_unused(pxPreviousWakeTime, xTimeIncrement);
}
// QUEUE
struct QueueDefinition;
using QueueHandle_t = QueueDefinition*;

inline auto xQueueCreate(UBaseType_t uxQueueLength, UBaseType_t uxItemSize)
    -> QueueHandle_t
{
    etl::ignore_unused(uxQueueLength, uxItemSize);
    return nullptr;
}

inline auto vQueueDelete(QueueHandle_t xQueue) -> void
{
    etl::ignore_unused(xQueue);
}

inline auto xQueueSend(QueueHandle_t xQueue, void const* pvItemToQueue,
    TickType_t xTicksToWait) -> BaseType_t
{
    etl::ignore_unused(xQueue, pvItemToQueue, xTicksToWait);
    return pdFALSE;
}

inline auto xQueueReceive(
    QueueHandle_t xQueue, void* pvBuffer, TickType_t xTicksToWait) -> BaseType_t
{
    etl::ignore_unused(xQueue, pvBuffer, xTicksToWait);
    return pdFALSE;
}

inline auto xQueueReset(QueueHandle_t xQueue) -> BaseType_t
{
    etl::ignore_unused(xQueue);
    return pdPASS;
}

inline auto uxQueueMessagesWaiting(QueueHandle_t xQueue) -> UBaseType_t
{
    etl::ignore_unused(xQueue);
    return 0;
}

// STREAM_BUFFER
struct StreamBufferDef_t;
using StreamBufferHandle_t = StreamBufferDef_t*;

[[nodiscard]] inline auto xStreamBufferCreate(etl::size_t bufferSizeBytes,
    etl::size_t triggerLevelBytes) -> StreamBufferHandle_t
{
    etl::ignore_unused(bufferSizeBytes, triggerLevelBytes);
    return {};
}

[[nodiscard]] inline auto xStreamBufferSend(StreamBufferHandle_t handle,
    const void* data, etl::size_t size, TickType_t ticksToWait) -> etl::size_t
{
    etl::ignore_unused(handle, data, size, ticksToWait);
    return 0;
}

[[nodiscard]] inline auto xStreamBufferSendFromISR(StreamBufferHandle_t handle,
    const void* data, etl::size_t size, BaseType_t* prio) -> etl::size_t
{
    etl::ignore_unused(handle, data, size, prio);
    return 0;
}

[[nodiscard]] inline auto xStreamBufferReceive(StreamBufferHandle_t handle,
    void* data, etl::size_t size, TickType_t ticks) -> etl::size_t
{
    etl::ignore_unused(handle, data, size, ticks);
    return 0;
}

[[nodiscard]] inline auto xStreamBufferReceiveFromISR(
    StreamBufferHandle_t handle, void* data, etl::size_t size, BaseType_t* prio)
    -> etl::size_t
{
    etl::ignore_unused(handle, data, size, prio);
    return 0;
}

inline auto vStreamBufferDelete(StreamBufferHandle_t handle) -> void
{
    etl::ignore_unused(handle);
}

[[nodiscard]] inline auto xStreamBufferBytesAvailable(
    StreamBufferHandle_t handle) -> etl::size_t
{
    etl::ignore_unused(handle);
    return {};
}

[[nodiscard]] inline auto xStreamBufferSpacesAvailable(
    StreamBufferHandle_t handle) -> etl::size_t
{
    etl::ignore_unused(handle);
    return {};
}

inline auto xStreamBufferSetTriggerLevel(
    StreamBufferHandle_t handle, etl::size_t triggerLevel) -> BaseType_t
{
    etl::ignore_unused(handle, triggerLevel);
    return {};
}

inline auto xStreamBufferReset(StreamBufferHandle_t handle) -> BaseType_t
{
    etl::ignore_unused(handle);
    return {};
}

[[nodiscard]] inline auto xStreamBufferIsEmpty(StreamBufferHandle_t handle)
    -> BaseType_t
{
    etl::ignore_unused(handle);
    return {};
}

[[nodiscard]] inline auto xStreamBufferIsFull(StreamBufferHandle_t handle)
    -> BaseType_t
{
    etl::ignore_unused(handle);
    return {};
}

// MESSAGE_BUFFER
using MessageBufferHandle_t = void*;

[[nodiscard]] inline auto xMessageBufferCreate(etl::size_t bufferSizeBytes)
    -> MessageBufferHandle_t
{
    etl::ignore_unused(bufferSizeBytes);
    return {};
}

#endif // TETL_FREERTOS_STUBS_HPP
