// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STDEXCEPT_OUT_OF_RANGE_HPP
#define TETL_STDEXCEPT_OUT_OF_RANGE_HPP

#include "etl/_stdexcept/logic_error.hpp"

namespace etl {

struct out_of_range : logic_error {
    constexpr out_of_range() = default;

    constexpr explicit out_of_range(char const* what) : logic_error{what} { }
};

} // namespace etl

#endif // TETL_STDEXCEPT_OUT_OF_RANGE_HPP
