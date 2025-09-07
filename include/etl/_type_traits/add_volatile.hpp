// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_TYPE_TRAITS_ADD_VOLATILE_HPP
#define TETL_TYPE_TRAITS_ADD_VOLATILE_HPP

namespace etl {

/// \brief Provides the member typedef type which is the same as T, except it
/// has a cv-qualifier added (unless T is a function, a reference, or already
/// has this cv-qualifier). Adds volatile.
///
/// \headerfile etl/type_traits.hpp
template <typename T>
struct add_volatile {
    using type = T volatile;
};

/// \relates add_volatile
template <typename T>
using add_volatile_t = typename add_volatile<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_ADD_VOLATILE_HPP
