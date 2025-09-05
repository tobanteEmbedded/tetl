// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/experimental/hardware/stm32/interrupt.hpp>
#endif

using namespace etl::experimental::hardware;

static bool dummyHandler01_WasCalled = false;

static void dummy_handler()
{
    dummyHandler01_WasCalled = true;
}

static auto test_all() -> bool
{
    auto callbacks                                      = stm32::isr::vector_t{};
    callbacks[static_cast<size_t>(stm32::isr_ids::nmi)] = dummy_handler;

    CHECK_FALSE(dummyHandler01_WasCalled);
    stm32::isr::call(callbacks, stm32::isr_ids::nmi);
    CHECK(dummyHandler01_WasCalled);

    return true;
}

auto main() -> int
{
    CHECK(test_all());
    return 0;
}
