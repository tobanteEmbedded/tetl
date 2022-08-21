/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTDDEF_MAX_ALIGN_T_HPP
#define TETL_CSTDDEF_MAX_ALIGN_T_HPP

#include "etl/_config/all.hpp"

namespace etl {

#if defined(TETL_MSVC)
    // Padding was added at the end of a structure
    #pragma warning(disable : 4324)
#endif

/// \brief etl::max_align_t is a trivial standard-layout type whose alignment
/// requirement is at least as strict (as large) as that of every scalar type.
///
/// https://en.cppreference.com/w/cpp/types/max_align_t
struct alignas(long double) max_align_t { };

#if defined(TETL_MSVC)
    // Padding was added at the end of a structure
    #pragma warning(default : 4324)
#endif

} // namespace etl

#endif // TETL_CSTDDEF_MAX_ALIGN_T_HPP