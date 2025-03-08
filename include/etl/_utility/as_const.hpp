// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_UTILITY_AS_CONST_HPP
#define TETL_UTILITY_AS_CONST_HPP

#include <etl/_type_traits/add_const.hpp>

namespace etl {

/// \brief Forms lvalue reference to const type of t.
template <typename T>
[[nodiscard]] constexpr auto as_const(T& t) noexcept -> add_const_t<T>&
{
    return t; // NOLINT(bugprone-return-const-ref-from-parameter)
}

template <typename T>
constexpr auto as_const(T const&&) -> void = delete;

} // namespace etl

#endif // TETL_UTILITY_AS_CONST_HPP
