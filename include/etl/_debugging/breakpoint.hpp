// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_DEBUGGING_BREAKPOINT_HPP
#define TETL_DEBUGGING_BREAKPOINT_HPP

#include <etl/_config/all.hpp>

namespace etl {

/// Unconditional breakpoint: attempts to temporarily halt the execution of
/// the program and transfer control to the debugger.
/// \ingroup debugging
inline auto breakpoint() noexcept -> void
{
    TETL_DEBUG_TRAP();
}

} // namespace etl

#endif // TETL_DEBUGGING_BREAKPOINT_HPP
