// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_EXPECTED_UNEXPECT_HPP
#define TETL_EXPECTED_UNEXPECT_HPP

namespace etl {

/// \ingroup expected
struct unexpect_t {
    unexpect_t() = default;
};

/// \relates unexpect_t
/// \ingroup expected
inline constexpr auto unexpect = unexpect_t{};

} // namespace etl

#endif // TETL_EXPECTED_UNEXPECT_HPP
