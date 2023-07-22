// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_LINALG_TAGS_HPP
#define TETL_LINALG_TAGS_HPP

namespace etl::linalg {

struct column_major_t {
    explicit column_major_t() = default;
};

inline constexpr auto column_major = column_major_t {};

struct row_major_t {
    explicit row_major_t() = default;
};

inline constexpr auto row_major = row_major_t {};

struct upper_triangle_t {
    explicit upper_triangle_t() = default;
};

inline constexpr auto upper_triangle = upper_triangle_t {};

struct lower_triangle_t {
    explicit lower_triangle_t() = default;
};

inline constexpr auto lower_triangle = lower_triangle_t {};

struct implicit_unit_diagonal_t {
    explicit implicit_unit_diagonal_t() = default;
};

inline constexpr auto implicit_unit_diagonal = implicit_unit_diagonal_t {};

struct explicit_diagonal_t {
    explicit explicit_diagonal_t() = default;
};

inline constexpr auto explicit_diagonal = explicit_diagonal_t {};

} // namespace etl::linalg

#endif // TETL_LINALG_TAGS_HPP
