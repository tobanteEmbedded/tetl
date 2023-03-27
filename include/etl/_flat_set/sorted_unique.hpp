/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_FLAT_SET_SORTED_UNIQUE_HPP
#define TETL_FLAT_SET_SORTED_UNIQUE_HPP

namespace etl {

struct sorted_unique_t {
    explicit sorted_unique_t() = default;
};

inline constexpr auto sorted_unique = sorted_unique_t {};

} // namespace etl

#endif // TETL_FLAT_SET_SORTED_UNIQUE_HPP
