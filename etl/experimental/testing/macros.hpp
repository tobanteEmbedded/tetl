// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef ETL_EXPERIMENTAL_TESTING_MACROS_HPP
#define ETL_EXPERIMENTAL_TESTING_MACROS_HPP

#include "etl/version.hpp"

#include "etl/experimental/testing/assertion_handler.hpp"
#include "etl/experimental/testing/name_and_tags.hpp"
#include "etl/experimental/testing/session.hpp"
#include "etl/experimental/testing/source_line_info.hpp"

// The goal of this macro is to avoid evaluation of the arguments, but
// still have the compiler warn on problems inside...
#if !defined(TEST_DETAIL_IGNORE_BUT_WARN)
#define TEST_DETAIL_IGNORE_BUT_WARN(...)
#endif

#define TEST_DETAIL_SESSION(name, size)                                        \
    static auto g_session_buffer = ::etl::test::session_buffer<size> {};       \
    static auto g_session = ::etl::test::session { g_session_buffer, name }

#define TEST_DETAIL_SESSION_RUN(argc, argv)                                    \
    [argc, argv] {                                                             \
        ::etl::ignore_unused(argc, argv);                                      \
        return g_session.run_all();                                            \
    }()

#define TEST_DETAIL_TEST_CASE2(tc, ...)                                        \
    static auto tc(::etl::test::context& session_context)->void;               \
    namespace {                                                                \
    auto TETL_ANONYMOUS_VAR(tc) = ::etl::test::auto_reg {                      \
        g_session,                                                             \
        ::etl::test::name_and_tags { __VA_ARGS__ },                            \
        tc,                                                                    \
    };                                                                         \
    }                                                                          \
    static auto tc(::etl::test::context& session_context)->void

#define TEST_DETAIL_TEST_CASE(...)                                             \
    TEST_DETAIL_TEST_CASE2(TETL_ANONYMOUS_VAR(tc), __VA_ARGS__)

#define TEST_DETAIL_SECTION2(tc, ...) if (true)

#define TEST_DETAIL_SECTION(...)                                               \
    TEST_DETAIL_SECTION2(TETL_ANONYMOUS_VAR(tc_section), __VA_ARGS__)

#define TEST_DETAIL_CHECK(disposition, ...)                                    \
    do {                                                                       \
        TEST_DETAIL_IGNORE_BUT_WARN(__VA_ARGS__);                              \
        ::etl::test::assertion_handler handler {                               \
            session_context,                                                   \
            TEST_DETAIL_SOURCE_LINE_INFO,                                      \
            disposition,                                                       \
            TETL_STRINGIFY(__VA_ARGS__),                                       \
            static_cast<bool>(!!(__VA_ARGS__)),                                \
        };                                                                     \
    } while (false)

// clang-format off
#define TEST_SESSION(name, size)        TEST_DETAIL_SESSION(name, size)
#define TEST_SESSION_RUN(argc, argv)    TEST_DETAIL_SESSION_RUN(argc, argv)

#define TEST_CASE(...)  TEST_DETAIL_TEST_CASE(__VA_ARGS__)

#define SECTION(...)  TEST_DETAIL_SECTION(__VA_ARGS__)

#define CHECK(...)      TEST_DETAIL_CHECK(::etl::test::result_disposition::continue_on_failure, __VA_ARGS__)
#define REQUIRE(...)    TEST_DETAIL_CHECK(::etl::test::result_disposition::normal, __VA_ARGS__)

#define CHECK_FALSE(...)    TEST_DETAIL_CHECK((::etl::test::result_disposition::flags{::etl::test::result_disposition::continue_on_failure | ::etl::test::result_disposition::false_test }), __VA_ARGS__)
#define REQUIRE_FALSE(...)  TEST_DETAIL_CHECK((::etl::test::result_disposition::flags{::etl::test::result_disposition::normal | ::etl::test::result_disposition::false_test }), __VA_ARGS__)

#define CHECK_EQUAL(lhs, rhs)       CHECK((lhs) == (rhs))
#define REQUIRE_EQUAL(lhs, rhs)     REQUIRE((lhs) == (rhs))

#define CHECK_NOT_EQUAL(lhs, rhs)   CHECK_FALSE((lhs) == (rhs))
#define REQUIRE_NOT_EQUAL(lhs, rhs) REQUIRE_FALSE((lhs) == (rhs))
// clang-format on

#endif // ETL_EXPERIMENTAL_TESTING_MACROS_HPP
