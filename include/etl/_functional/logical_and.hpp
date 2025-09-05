// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FUNCTIONAL_LOGICAL_AND_HPP
#define TETL_FUNCTIONAL_LOGICAL_AND_HPP

#include <etl/_utility/forward.hpp>

namespace etl {

/// \brief Function object for performing logical AND (logical conjunction).
/// Effectively calls operator&& on type T.
/// https://en.cppreference.com/w/cpp/utility/functional/logical_and
template <typename T = void>
struct logical_and {
    [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> bool
    {
        return lhs && rhs;
    }
};

template <>
struct logical_and<void> {
    using is_transparent = void;

    template <typename T, typename U>
    [[nodiscard]] constexpr auto
    operator()(T&& lhs, U&& rhs) const noexcept(noexcept(etl::forward<T>(lhs) && etl::forward<U>(rhs)))
        -> decltype(etl::forward<T>(lhs) && etl::forward<U>(rhs))
    {
        return etl::forward<T>(lhs) && etl::forward<U>(rhs);
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_LOGICAL_AND_HPP
