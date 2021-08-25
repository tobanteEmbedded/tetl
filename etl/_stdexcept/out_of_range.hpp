/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_STDEXCEPT_OUT_OF_RANGE_HPP
#define TETL_STDEXCEPT_OUT_OF_RANGE_HPP

#include "etl/_stdexcept/logic_error.hpp"

namespace etl {

struct out_of_range : logic_error {
    constexpr out_of_range() = default;
    constexpr explicit out_of_range(char const* what) : logic_error { what } { }
};

} // namespace etl

#endif // TETL_STDEXCEPT_OUT_OF_RANGE_HPP