// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_VARIANT_MONOSTATE_HPP
#define TETL_VARIANT_MONOSTATE_HPP

#include <etl/_compare/strong_ordering.hpp>

namespace etl {

/// \brief Unit type intended for use as a well-behaved empty alternative in
/// etl::variant. In particular, a variant of non-default-constructible types
/// may list etl::monostate as its first alternative: this makes the variant
/// itself default-constructible
///
/// \headerfile etl/variant.hpp
struct monostate {
    /// \brief All instances of etl::monostate compare equal.
    [[nodiscard]] friend constexpr auto operator==(monostate /*l*/, monostate /*r*/) noexcept -> bool
    {
        return true;
    }

    /// \brief All instances of etl::monostate compare equal.
    [[nodiscard]] friend constexpr auto operator<=>(monostate /*l*/, monostate /*r*/) noexcept -> etl::strong_ordering
    {
        return etl::strong_ordering::equal;
    }
};

} // namespace etl

#endif // TETL_VARIANT_MONOSTATE_HPP
