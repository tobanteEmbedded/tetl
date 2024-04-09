// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_ADD_CONST_HPP
#define TETL_TYPE_TRAITS_ADD_CONST_HPP

namespace etl {

/// \brief Provides the member typedef type which is the same as T, except it
/// has a cv-qualifier added (unless T is a function, a reference, or already
/// has this cv-qualifier). Adds const.
template <typename T>
struct add_const {
    using type = T const;
};

/// \relates add_const
template <typename T>
using add_const_t = typename add_const<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_ADD_CONST_HPP
