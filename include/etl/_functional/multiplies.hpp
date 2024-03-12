// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FUNCTIONAL_MULTIPLIES_HPP
#define TETL_FUNCTIONAL_MULTIPLIES_HPP

#include <etl/_utility/forward.hpp>

namespace etl {

/// \brief Function object for performing multiplication. Effectively calls
/// operator* on two instances of type T.
/// https://en.cppreference.com/w/cpp/utility/functional/multiplies
template <typename T = void>
struct multiplies {
    /// \brief Returns the product between lhs and rhs.
    [[nodiscard]] constexpr auto operator()(T const& lhs, T const& rhs) const -> T { return lhs * rhs; }
};

template <>
struct multiplies<void> {
    using is_transparent = void;

    /// \brief Returns the product between lhs and rhs.
    template <typename T, typename U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        noexcept(noexcept(TETL_FORWARD(lhs) * TETL_FORWARD(rhs))) -> decltype(TETL_FORWARD(lhs) * TETL_FORWARD(rhs))
    {
        return TETL_FORWARD(lhs) * TETL_FORWARD(rhs);
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_MULTIPLIES_HPP
