// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_ADD_CONST_HPP
#define TETL_TYPE_TRAITS_ADD_CONST_HPP

namespace etl {

/// \relates add_const
template <typename T>
using add_const_t = T const;

/// \brief Provides the member typedef type which is the same as T, except it
/// has a cv-qualifier added (unless T is a function, a reference, or already
/// has this cv-qualifier). Adds const.
template <typename T>
struct add_const {
    using type = add_const_t<T>;
};

} // namespace etl

#endif // TETL_TYPE_TRAITS_ADD_CONST_HPP
