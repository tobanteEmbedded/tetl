// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STDEXCEPT_OVERFLOW_ERROR_HPP
#define TETL_STDEXCEPT_OVERFLOW_ERROR_HPP

#include "etl/_stdexcept/runtime_error.hpp"

namespace etl {

struct overflow_error : runtime_error {
    constexpr overflow_error() = default;
    constexpr explicit overflow_error(char const* what) : runtime_error { what } { }
};

} // namespace etl

#endif // TETL_STDEXCEPT_OVERFLOW_ERROR_HPP
