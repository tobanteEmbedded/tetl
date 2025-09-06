// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_CSTDDEF_PTRDIFF_T_HPP
#define TETL_CSTDDEF_PTRDIFF_T_HPP

#include <etl/_config/all.hpp>

namespace etl {

/// \brief etl::ptrdiff_t is the signed integer type of the result of
/// subtracting two pointers.
///
/// https://en.cppreference.com/w/cpp/types/ptrdiff_t
using ptrdiff_t = TETL_BUILTIN_PTRDIFF;

} // namespace etl

#endif // TETL_CSTDDEF_PTRDIFF_T_HPP
