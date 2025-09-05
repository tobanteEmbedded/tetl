// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FUNCTIONAL_LOGICAL_NOT_HPP
#define TETL_FUNCTIONAL_LOGICAL_NOT_HPP

#include <etl/_utility/forward.hpp>

namespace etl {

/// \brief Function object for performing logical NOT (logical negation).
/// Effectively calls operator! for type T.
/// https://en.cppreference.com/w/cpp/utility/functional/logical_not
template <typename T = void>
struct logical_not {
    [[nodiscard]] constexpr auto operator()(T const& arg) const -> bool
    {
        return !arg;
    }
};

template <>
struct logical_not<void> {
    using is_transparent = void;

    template <typename T>
    [[nodiscard]] constexpr auto operator()(T&& arg) const noexcept(noexcept(!etl::forward<T>(arg)))
        -> decltype(!etl::forward<T>(arg))
    {
        return !etl::forward<T>(arg);
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_LOGICAL_NOT_HPP
