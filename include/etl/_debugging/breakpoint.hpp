// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_DEBUGGING_BREAKPOINT_HPP
#define TETL_DEBUGGING_BREAKPOINT_HPP

#include <etl/_config/all.hpp>

namespace etl {

inline auto breakpoint() noexcept -> void { TETL_DEBUG_TRAP(); }

} // namespace etl

#endif // TETL_DEBUGGING_BREAKPOINT_HPP
