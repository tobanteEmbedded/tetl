// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#ifndef TETL_TEST_EXCEPTION_HPP
#define TETL_TEST_EXCEPTION_HPP

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/cmath.hpp>
    #include <etl/exception.hpp>
    #include <etl/string_view.hpp>
    #include <etl/type_traits.hpp>
#endif

#define CHECK_EXCEPTION_TYPE(ExceptionType, BaseType)                                                                  \
    do {                                                                                                               \
        CHECK(etl::is_default_constructible_v<ExceptionType>);                                                         \
        CHECK(etl::is_constructible_v<ExceptionType, char const*>);                                                    \
        CHECK(etl::is_base_of_v<BaseType, ExceptionType>);                                                             \
        CHECK(etl::is_base_of_v<etl::exception, ExceptionType>);                                                       \
        auto const e = ExceptionType{"test"};                                                                          \
        CHECK(e.what() == etl::string_view("test"));                                                                   \
    } while (false)

#endif // TETL_TEST_EXCEPTION_HPP
