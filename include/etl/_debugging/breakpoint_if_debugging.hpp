// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_DEBUGGING_BREAKPOINT_IF_DEBUGGING_HPP
#define TETL_DEBUGGING_BREAKPOINT_IF_DEBUGGING_HPP

#include <etl/_debugging/breakpoint.hpp>
#include <etl/_debugging/is_debugger_present.hpp>

namespace etl {

/// Conditional breakpoint: attempts to temporarily halt the execution of the
/// program and transfer control to the debugger if it were able to determine
/// that the debugger is present. Acts as a no-op otherwise.
/// \ingroup debugging
inline auto breakpoint_if_debugging() noexcept -> void
{
    if (etl::is_debugger_present()) {
        etl::breakpoint();
    }
}

} // namespace etl

#endif // TETL_DEBUGGING_BREAKPOINT_IF_DEBUGGING_HPP
