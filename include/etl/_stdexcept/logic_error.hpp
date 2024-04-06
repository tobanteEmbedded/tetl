// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_STDEXCEPT_LOGIC_ERROR_HPP
#define TETL_STDEXCEPT_LOGIC_ERROR_HPP

#include <etl/_exception/exception.hpp>

namespace etl {

struct logic_error : exception {
    constexpr logic_error() = default;

    constexpr explicit logic_error(char const* what)
        : exception{what}
    {
    }
};

} // namespace etl

#endif // TETL_STDEXCEPT_LOGIC_ERROR_HPP
