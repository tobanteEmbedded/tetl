// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STDEXCEPT_DOMAIN_ERROR_HPP
#define TETL_STDEXCEPT_DOMAIN_ERROR_HPP

#include <etl/_stdexcept/logic_error.hpp>

namespace etl {

struct domain_error : logic_error {
    constexpr domain_error() = default;

    constexpr explicit domain_error(char const* what) : logic_error{what} { }
};

} // namespace etl

#endif // TETL_STDEXCEPT_DOMAIN_ERROR_HPP
