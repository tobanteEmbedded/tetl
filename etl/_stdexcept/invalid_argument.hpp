/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_STDEXCEPT_INVALID_ARGUMENT_HPP
#define TETL_STDEXCEPT_INVALID_ARGUMENT_HPP

#include "etl/_stdexcept/logic_error.hpp"

namespace etl {

struct invalid_argument : logic_error {
    constexpr invalid_argument() = default;
    constexpr explicit invalid_argument(char const* what) : logic_error { what } { }
};

} // namespace etl

#endif // TETL_STDEXCEPT_INVALID_ARGUMENT_HPP