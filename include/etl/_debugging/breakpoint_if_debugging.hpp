// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_DEBUGGING_BREAKPOINT_IF_DEBUGGING_HPP
#define TETL_DEBUGGING_BREAKPOINT_IF_DEBUGGING_HPP

#include <etl/_debugging/breakpoint.hpp>
#include <etl/_debugging/is_debugger_present.hpp>

namespace etl {

inline auto breakpoint_if_debugging() noexcept -> void
{
    if (etl::is_debugger_present()) {
        etl::breakpoint();
    }
}

} // namespace etl

#endif // TETL_DEBUGGING_BREAKPOINT_IF_DEBUGGING_HPP
