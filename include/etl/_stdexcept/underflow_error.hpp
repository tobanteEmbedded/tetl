// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STDEXCEPT_UNDERFLOW_ERROR_HPP
#define TETL_STDEXCEPT_UNDERFLOW_ERROR_HPP

#include <etl/_stdexcept/runtime_error.hpp>

namespace etl {

struct underflow_error : runtime_error {
    constexpr underflow_error() = default;

    constexpr explicit underflow_error(char const* what)
        : runtime_error{what}
    {
    }
};

} // namespace etl

#endif // TETL_STDEXCEPT_UNDERFLOW_ERROR_HPP
