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

#ifndef TAETL_RTOS_STUBS_HPP
#define TAETL_RTOS_STUBS_HPP

#include "taetl/warning.hpp"

// BASE
using BaseType_t             = long;
using UBaseType_t            = unsigned long;
using configSTACK_DEPTH_TYPE = taetl::uint16_t;
#define pdFALSE ((BaseType_t)0)
#define pdTRUE ((BaseType_t)1)
#define pdPASS (pdTRUE)
#define pdFAIL (pdFALSE)
#define errQUEUE_EMPTY ((BaseType_t)0)
#define errQUEUE_FULL ((BaseType_t)0)

// TICK
using TickType_t = uint32_t;

// TASK
struct tskTaskControlBlock;

using TaskHandle_t   = tskTaskControlBlock*;
using TaskFunction_t = void (*)(void*);

inline auto xTaskCreate(TaskFunction_t pvTaskCode, const char* const pcName,
                        configSTACK_DEPTH_TYPE usStackDepth,
                        void* const pvParameters, UBaseType_t uxPriority,
                        TaskHandle_t* const pxCreatedTask) -> BaseType_t
{
    taetl::ignore_unused(pvTaskCode, pcName, usStackDepth, pvParameters,
                         uxPriority, pxCreatedTask);
    return pdFALSE;
}

inline auto vTaskDelete(TaskHandle_t xTask) -> void
{
    taetl::ignore_unused(xTask);
}

inline auto vTaskStartScheduler() -> void { }

inline auto vTaskDelay(const TickType_t xTicksToDelay) -> void
{
    taetl::ignore_unused(xTicksToDelay);
}

inline auto vTaskDelayUntil(TickType_t* const pxPreviousWakeTime,
                            const TickType_t xTimeIncrement) -> void
{
    taetl::ignore_unused(pxPreviousWakeTime, xTimeIncrement);
}
// QUEUE
struct QueueDefinition;
using QueueHandle_t = QueueDefinition*;

inline auto xQueueCreate(UBaseType_t uxQueueLength, UBaseType_t uxItemSize)
    -> QueueHandle_t
{
    taetl::ignore_unused(uxQueueLength, uxItemSize);
    return nullptr;
}

inline auto vQueueDelete(QueueHandle_t xQueue) -> void
{
    taetl::ignore_unused(xQueue);
}

inline auto xQueueSend(QueueHandle_t xQueue, const void* pvItemToQueue,
                       TickType_t xTicksToWait) -> BaseType_t
{
    taetl::ignore_unused(xQueue, pvItemToQueue, xTicksToWait);
    return pdFALSE;
}

inline auto xQueueReceive(QueueHandle_t xQueue, void* pvBuffer,
                          TickType_t xTicksToWait) -> BaseType_t
{
    taetl::ignore_unused(xQueue, pvBuffer, xTicksToWait);
    return pdFALSE;
}

inline auto xQueueReset(QueueHandle_t xQueue) -> BaseType_t
{
    taetl::ignore_unused(xQueue);
    return pdPASS;
}

inline auto uxQueueMessagesWaiting(QueueHandle_t xQueue) -> UBaseType_t
{
    taetl::ignore_unused(xQueue);
    return 0;
}

#endif  // TAETL_RTOS_STUBS_HPP
