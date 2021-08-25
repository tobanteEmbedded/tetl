/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_STDEXCEPT_RUNTIME_ERROR_HPP
#define TETL_STDEXCEPT_RUNTIME_ERROR_HPP

#include "etl/_exception/exception.hpp"

namespace etl {

struct runtime_error : exception {
    constexpr runtime_error() = default;
    constexpr explicit runtime_error(char const* what) : exception { what } { }
};

} // namespace etl

#endif // TETL_STDEXCEPT_RUNTIME_ERROR_HPP