// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_FUNCTIONAL_IDENTITY_HPP
#define TETL_FUNCTIONAL_IDENTITY_HPP

#include <etl/_utility/forward.hpp>

namespace etl {

/// \brief etl::identity is a function object type whose operator() returns its
/// argument unchanged.
struct identity {
    using is_transparent = void;

    template <typename T>
    [[nodiscard]] constexpr auto operator()(T&& t) const noexcept -> T&&
    {
        return etl::forward<T>(t);
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_IDENTITY_HPP
