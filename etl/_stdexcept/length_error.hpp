/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_STDEXCEPT_LENGTH_ERROR_HPP
#define TETL_STDEXCEPT_LENGTH_ERROR_HPP

#include "etl/_stdexcept/logic_error.hpp"

namespace etl {

struct length_error : logic_error {
    constexpr length_error() = default;
    constexpr explicit length_error(char const* what) : logic_error { what } { }
};

} // namespace etl

#endif // TETL_STDEXCEPT_LENGTH_ERROR_HPP
