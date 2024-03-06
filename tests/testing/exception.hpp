// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TEST_EXCEPTION_HPP
#define TETL_TEST_EXCEPTION_HPP

#include <etl/cmath.hpp>

#include <etl/exception.hpp>
#include <etl/string_view.hpp>
#include <etl/type_traits.hpp>

#define TEST_EXCEPTION(type, base)                                                                                     \
    do {                                                                                                               \
        assert((etl::is_default_constructible_v<type>));                                                               \
        assert((etl::is_constructible_v<type, char const*>));                                                          \
        assert((etl::is_base_of_v<base, type>));                                                                       \
        assert((etl::is_base_of_v<etl::exception, type>));                                                             \
        auto const e = type {"test"};                                                                                  \
        assert(e.what() == etl::string_view("test"));                                                                  \
    } while (false)

#endif // TETL_TEST_EXCEPTION_HPP
