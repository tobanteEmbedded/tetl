// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STDEXCEPT_RANGE_ERROR_HPP
#define TETL_STDEXCEPT_RANGE_ERROR_HPP

#include <etl/_stdexcept/runtime_error.hpp>

namespace etl {

struct range_error : runtime_error {
    constexpr range_error() = default;

    constexpr explicit range_error(char const* what) : runtime_error{what} { }
};

} // namespace etl

#endif // TETL_STDEXCEPT_RANGE_ERROR_HPP
