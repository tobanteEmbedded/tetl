// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FUNCTIONAL_DIVIDES_HPP
#define TETL_FUNCTIONAL_DIVIDES_HPP

#include <etl/_utility/forward.hpp>

namespace etl {

/// \brief Function object for performing division. Effectively calls operator/
/// on two instances of type T.
/// https://en.cppreference.com/w/cpp/utility/functional/divides
template <typename T = void>
struct divides {
    [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T { return static_cast<T>(lhs / rhs); }
};

template <>
struct divides<void> {
    using is_transparent = void;

    template <typename T, typename U>
    [[nodiscard]] constexpr auto
    operator()(T&& lhs, U&& rhs) const noexcept(noexcept(etl::forward<T>(lhs) / etl::forward<U>(rhs)))
        -> decltype(etl::forward<T>(lhs) / etl::forward<U>(rhs))
    {
        return etl::forward<T>(lhs) / etl::forward<U>(rhs);
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_DIVIDES_HPP
