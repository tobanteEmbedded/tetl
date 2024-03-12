// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STDEXCEPT_INVALID_ARGUMENT_HPP
#define TETL_STDEXCEPT_INVALID_ARGUMENT_HPP

#include "etl/_stdexcept/logic_error.hpp"

namespace etl {

struct invalid_argument : logic_error {
    constexpr invalid_argument() = default;

    constexpr explicit invalid_argument(char const* what) : logic_error{what} { }
};

} // namespace etl

#endif // TETL_STDEXCEPT_INVALID_ARGUMENT_HPP
