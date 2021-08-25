/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TYPE_TRAITS_ADD_VOLATILE_HPP
#define TETL_TYPE_TRAITS_ADD_VOLATILE_HPP

namespace etl {

/// \brief Provides the member typedef type which is the same as T, except it
/// has a cv-qualifier added (unless T is a function, a reference, or already
/// has this cv-qualifier). Adds volatile.
/// \group add_volatile
template <typename T>
struct add_volatile {
    using type = T volatile;
};

/// \group add_volatile
template <typename T>
using add_volatile_t = typename add_volatile<T>::type;

} // namespace etl

#endif // TETL_TYPE_TRAITS_ADD_VOLATILE_HPP