// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_DEBUGGING_IS_DEBUGGER_PRESENT_HPP
#define TETL_DEBUGGING_IS_DEBUGGER_PRESENT_HPP

#include <etl/_config/all.hpp>

namespace etl {

/// Attempts to determine if the program is being executed with debugger present.
/// \ingroup debugging
[[nodiscard]] inline auto is_debugger_present() noexcept -> bool { return false; }

} // namespace etl

#endif // TETL_DEBUGGING_IS_DEBUGGER_PRESENT_HPP
