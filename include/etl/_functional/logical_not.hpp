// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

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
        return not arg;
    }
};

template <>
struct logical_not<void> {
    using is_transparent = void;

    template <typename T>
    [[nodiscard]] constexpr auto operator()(T&& arg) const noexcept(noexcept(not etl::forward<T>(arg)))
        -> decltype(not etl::forward<T>(arg))
    {
        return not etl::forward<T>(arg);
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_LOGICAL_NOT_HPP
