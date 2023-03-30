// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TYPE_TRAITS_ADD_VOLATILE_HPP
#define TETL_TYPE_TRAITS_ADD_VOLATILE_HPP

namespace etl {

template <typename T>
using add_volatile_t = T volatile;

/// \brief Provides the member typedef type which is the same as T, except it
/// has a cv-qualifier added (unless T is a function, a reference, or already
/// has this cv-qualifier). Adds volatile.
template <typename T>
struct add_volatile {
    using type = add_volatile_t<T>;
};

} // namespace etl

#endif // TETL_TYPE_TRAITS_ADD_VOLATILE_HPP
