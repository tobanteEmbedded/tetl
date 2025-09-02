// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FUNCTIONAL_MINUS_HPP
#define TETL_FUNCTIONAL_MINUS_HPP

#include <etl/_utility/forward.hpp>

namespace etl {

/// \brief Function object for performing subtraction. Effectively calls
/// operator- on two instances of type T.
/// https://en.cppreference.com/w/cpp/utility/functional/minus
template <typename T = void>
struct minus {
    /// \brief Returns the difference between lhs and rhs.
    [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T { return static_cast<T>(lhs - rhs); }
};

template <>
struct minus<void> {
    using is_transparent = void;

    /// \brief Returns the difference between lhs and rhs.
    template <typename T, typename U>
    [[nodiscard]] constexpr auto
    operator()(T&& lhs, U&& rhs) const noexcept(noexcept(etl::forward<T>(lhs) - etl::forward<U>(rhs)))
        -> decltype(etl::forward<T>(lhs) - etl::forward<U>(rhs))
    {
        return etl::forward<T>(lhs) - etl::forward<U>(rhs);
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_MINUS_HPP
