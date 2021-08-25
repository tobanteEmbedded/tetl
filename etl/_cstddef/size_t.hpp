/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTDDEF_SIZE_T_HPP
#define TETL_CSTDDEF_SIZE_T_HPP

#include "etl/_config/builtin_types.hpp"

namespace etl {

/// \brief etl::size_t is the unsigned integer type of the result of the sizeof
/// operator.
///
/// https://en.cppreference.com/w/cpp/types/size_t
using size_t = TETL_BUILTIN_SIZET;

} // namespace etl

#endif // TETL_CSTDDEF_SIZE_T_HPP