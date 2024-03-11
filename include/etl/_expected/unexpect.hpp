// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_EXPECTED_UNEXPECT_HPP
#define TETL_EXPECTED_UNEXPECT_HPP

namespace etl {

struct unexpect_t {
    unexpect_t() = default;
};

inline constexpr auto unexpect = unexpect_t {};

} // namespace etl

#endif // TETL_EXPECTED_UNEXPECT_HPP
