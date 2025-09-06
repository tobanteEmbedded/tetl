// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#ifndef TETL_CSTDDEF_MAX_ALIGN_T_HPP
#define TETL_CSTDDEF_MAX_ALIGN_T_HPP

#include <etl/_config/all.hpp>

namespace etl {

#if defined(TETL_COMPILER_MSVC)
    #pragma warning(disable: 4324) // Padding was added at the end of a structure
#endif

/// \brief etl::max_align_t is a trivial standard-layout type whose alignment
/// requirement is at least as strict (as large) as that of every scalar type.
///
/// https://en.cppreference.com/w/cpp/types/max_align_t
struct alignas(long double) max_align_t { };

#if defined(TETL_COMPILER_MSVC)
    #pragma warning(default: 4324) // Padding was added at the end of a structure
#endif

} // namespace etl

#endif // TETL_CSTDDEF_MAX_ALIGN_T_HPP
