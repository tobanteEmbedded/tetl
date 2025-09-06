// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_LINALG_TAGS_HPP
#define TETL_LINALG_TAGS_HPP

namespace etl::linalg {

/// \ingroup linalg
struct column_major_t {
    explicit column_major_t() = default;
};

/// \relates column_major_t
inline constexpr auto column_major = column_major_t{};

/// \ingroup linalg
struct row_major_t {
    explicit row_major_t() = default;
};

/// \relates struct row_major_t {
inline constexpr auto row_major = row_major_t{};

/// \ingroup linalg
struct upper_triangle_t {
    explicit upper_triangle_t() = default;
};

/// \relates upper_triangle_t
inline constexpr auto upper_triangle = upper_triangle_t{};

/// \ingroup linalg
struct lower_triangle_t {
    explicit lower_triangle_t() = default;
};

/// \relates lower_triangle_t
inline constexpr auto lower_triangle = lower_triangle_t{};

/// \ingroup linalg
struct implicit_unit_diagonal_t {
    explicit implicit_unit_diagonal_t() = default;
};

/// \relates implicit_unit_diagonal_t
inline constexpr auto implicit_unit_diagonal = implicit_unit_diagonal_t{};

/// \ingroup linalg
struct explicit_diagonal_t {
    explicit explicit_diagonal_t() = default;
};

/// \relates explicit_diagonal_t
inline constexpr auto explicit_diagonal = explicit_diagonal_t{};

} // namespace etl::linalg

#endif // TETL_LINALG_TAGS_HPP
