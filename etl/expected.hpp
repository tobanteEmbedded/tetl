/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_EXPECTED_HPP
#define TETL_EXPECTED_HPP

#include "etl/_config/all.hpp"

#include "etl/type_traits.hpp"

namespace etl {
struct unexpect_t {
    unexpect_t() = default;
};

inline constexpr unexpect_t unexpect {};

} // namespace etl
#endif // TETL_EXPECTED_HPP
