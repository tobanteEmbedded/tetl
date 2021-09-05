/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/experimental/hardware/stm32/interrupt.hpp"

#include "testing/testing.hpp"

using namespace etl::experimental::hardware;

static bool dummyHandler01_WasCalled = false;
static void dummy_handler() { dummyHandler01_WasCalled = true; }

auto test_all() -> bool
{
    auto callbacks = stm32::isr::vector_t {};
    callbacks[static_cast<size_t>(stm32::isr_ids::nmi)] = dummy_handler;

    assert(!dummyHandler01_WasCalled);
    stm32::isr::call(callbacks, stm32::isr_ids::nmi);
    assert(dummyHandler01_WasCalled);

    return true;
}

auto main() -> int
{
    assert(test_all());
    return 0;
}