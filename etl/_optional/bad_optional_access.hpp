/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_OPTIONAL_BAD_OPTIONAL_ACCESS_HPP
#define TETL_OPTIONAL_BAD_OPTIONAL_ACCESS_HPP

#include "etl/_exception/exception.hpp"

namespace etl {

/// \brief Defines a type of object to be thrown by etl::optional::value when
/// accessing an optional object that does not contain a value.
///
/// https://en.cppreference.com/w/cpp/utility/optional/bad_optional_access
struct bad_optional_access : etl::exception {
    constexpr bad_optional_access() = default;
    constexpr explicit bad_optional_access(char const* what) : exception { what } { }
};

} // namespace etl

#endif // TETL_OPTIONAL_BAD_OPTIONAL_ACCESS_HPP
