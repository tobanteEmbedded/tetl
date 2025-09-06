// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2024 Tobias Hienzsch

#ifndef TETL_FLAT_SET_SORTED_EQUIVALENT_HPP
#define TETL_FLAT_SET_SORTED_EQUIVALENT_HPP

namespace etl {

struct sorted_equivalent_t {
    explicit sorted_equivalent_t() = default;
};

inline constexpr auto sorted_equivalent = sorted_equivalent_t{};

} // namespace etl

#endif // TETL_FLAT_SET_SORTED_EQUIVALENT_HPP
