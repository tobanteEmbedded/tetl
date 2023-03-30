// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_CSTDDEF_SIZE_T_HPP
#define TETL_CSTDDEF_SIZE_T_HPP

#include "etl/_config/all.hpp"

namespace etl {

/// \brief etl::size_t is the unsigned integer type of the result of the sizeof
/// operator.
///
/// https://en.cppreference.com/w/cpp/types/size_t
using size_t = TETL_BUILTIN_SIZET;

} // namespace etl

#endif // TETL_CSTDDEF_SIZE_T_HPP
