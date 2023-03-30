// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_VARIANT_MONOSTATE_HPP
#define TETL_VARIANT_MONOSTATE_HPP

namespace etl {

/// \brief Unit type intended for use as a well-behaved empty alternative in
/// etl::variant. In particular, a variant of non-default-constructible types
/// may list etl::monostate as its first alternative: this makes the variant
/// itself default-constructible
struct monostate { };

/// \brief All instances of etl::monostate compare equal.
[[nodiscard]] constexpr auto operator==(monostate /*lhs*/, monostate /*rhs*/) noexcept -> bool { return true; }

/// \brief All instances of etl::monostate compare equal.
[[nodiscard]] constexpr auto operator!=(monostate /*lhs*/, monostate /*rhs*/) noexcept -> bool { return false; }

/// \brief All instances of etl::monostate compare equal.
[[nodiscard]] constexpr auto operator<(monostate /*lhs*/, monostate /*rhs*/) noexcept -> bool { return false; }

/// \brief All instances of etl::monostate compare equal.
[[nodiscard]] constexpr auto operator>(monostate /*lhs*/, monostate /*rhs*/) noexcept -> bool { return false; }

/// \brief All instances of etl::monostate compare equal.
[[nodiscard]] constexpr auto operator<=(monostate /*lhs*/, monostate /*rhs*/) noexcept -> bool { return true; }

/// \brief All instances of etl::monostate compare equal.
[[nodiscard]] constexpr auto operator>=(monostate /*lhs*/, monostate /*rhs*/) noexcept -> bool { return true; }

} // namespace etl

#endif // TETL_VARIANT_MONOSTATE_HPP
