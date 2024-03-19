// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TEST_EXCEPTION_HPP
#define TETL_TEST_EXCEPTION_HPP

#include <etl/cmath.hpp>

#include <etl/exception.hpp>
#include <etl/string_view.hpp>
#include <etl/type_traits.hpp>

#define TEST_EXCEPTION(ExceptionType, BaseType)                                                                        \
    do {                                                                                                               \
        ASSERT(etl::is_default_constructible_v<ExceptionType>);                                                        \
        ASSERT(etl::is_constructible_v<ExceptionType, char const*>);                                                   \
        ASSERT(etl::is_base_of_v<BaseType, ExceptionType>);                                                            \
        ASSERT(etl::is_base_of_v<etl::exception, ExceptionType>);                                                      \
        auto const e = ExceptionType{"test"};                                                                          \
        ASSERT(e.what() == etl::string_view("test"));                                                                  \
    } while (false)

#endif // TETL_TEST_EXCEPTION_HPP
