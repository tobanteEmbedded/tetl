/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_ADD_CONST_HPP
#define TETL_TYPE_TRAITS_ADD_CONST_HPP

namespace etl {

/// \brief Provides the member typedef type which is the same as T, except it
/// has a cv-qualifier added (unless T is a function, a reference, or already
/// has this cv-qualifier). Adds const.
/// \group add_const
template <typename T>
struct add_const {
    using type = T const;
};

/// \group add_const
template <typename T>
using add_const_t = typename add_const<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_ADD_CONST_HPP