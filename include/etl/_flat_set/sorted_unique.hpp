// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2019 Tobias Hienzsch

#ifndef TETL_FLAT_SET_SORTED_UNIQUE_HPP
#define TETL_FLAT_SET_SORTED_UNIQUE_HPP

namespace etl {

struct sorted_unique_t {
    explicit sorted_unique_t() = default;
};

inline constexpr auto sorted_unique = sorted_unique_t{};

} // namespace etl

#endif // TETL_FLAT_SET_SORTED_UNIQUE_HPP
