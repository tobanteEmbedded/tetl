// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_UTILITY_UNREACHABLE_HPP
#define TETL_UTILITY_UNREACHABLE_HPP

#include <etl/_config/all.hpp>

namespace etl {

[[noreturn]] inline auto unreachable() -> void
{
#if defined(_MSC_VER) and not defined(__clang__)
    __assume(false);
#else
    __builtin_unreachable();
#endif
}

} // namespace etl

#endif // TETL_UTILITY_UNREACHABLE_HPP
