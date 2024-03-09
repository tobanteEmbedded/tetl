// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_OPTIONAL_MAKE_OPTIONAL_HPP
#define TETL_OPTIONAL_MAKE_OPTIONAL_HPP

#include <etl/_optional/optional.hpp>
#include <etl/_type_traits/decay.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/in_place.hpp>

namespace etl {

/// \brief Creates an optional object from value.
template <typename T>
constexpr auto make_optional(T&& value) -> etl::optional<etl::decay_t<T>>
{
    return etl::optional<etl::decay_t<T>>(etl::forward<T>(value));
}

/// \brief Creates an optional object constructed in-place from args...
template <typename T, typename... Args>
constexpr auto make_optional(Args&&... args) -> etl::optional<T>
{
    return etl::optional<T>(etl::in_place, etl::forward<Args>(args)...);
}

} // namespace etl

#endif // TETL_OPTIONAL_MAKE_OPTIONAL_HPP
