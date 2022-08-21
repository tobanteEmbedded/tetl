/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TEST_EXCEPTION_HPP
#define TETL_TEST_EXCEPTION_HPP

#include "etl/cmath.hpp"

#include "etl/cassert.hpp"
#include "etl/exception.hpp"
#include "etl/string_view.hpp"
#include "etl/type_traits.hpp"

#define TEST_EXCEPTION(type, base)                                                                                     \
    do {                                                                                                               \
        assert((etl::is_default_constructible_v<type>));                                                               \
        assert((etl::is_constructible_v<type, char const*>));                                                          \
        assert((etl::is_base_of_v<base, type>));                                                                       \
        assert((etl::is_base_of_v<etl::exception, type>));                                                             \
        auto const e = type { "test" };                                                                                \
        assert(e.what() == etl::string_view("test"));                                                                  \
    } while (false)

#endif // TETL_TEST_EXCEPTION_HPP
