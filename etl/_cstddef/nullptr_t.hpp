/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_CSTDDEF_NULLPTR_T_HPP
#define TETL_CSTDDEF_NULLPTR_T_HPP

namespace etl {

/// \brief etl::nullptr_t is the type of the null pointer literal, nullptr. It
/// is a distinct type that is not itself a pointer type or a pointer to member
/// type.
///
/// https://en.cppreference.com/w/cpp/types/nullptr_t
using nullptr_t = decltype(nullptr);

} // namespace etl

#endif // TETL_CSTDDEF_NULLPTR_T_HPP