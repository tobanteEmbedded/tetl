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

#ifndef ETL_EXPERIMENTAL_TESTING_TESTING_HPP
#define ETL_EXPERIMENTAL_TESTING_TESTING_HPP

#include "etl/version.hpp"

#include "etl/array.hpp"
#include "etl/cstddef.hpp"
#include "etl/string_view.hpp"

#include <stdio.h>

// The goal of this macro is to avoid evaluation of the arguments, but
// still have the compiler warn on problems inside...
#if !defined(TEST_DETAIL_IGNORE_BUT_WARN)
#define TEST_DETAIL_IGNORE_BUT_WARN(...)
#endif

namespace etl::test {

struct context;

using test_func_t = void (*)(context&);

struct name_and_tags {
    name_and_tags(::etl::string_view const& n = ::etl::string_view(),
        ::etl::string_view const& t           = ::etl::string_view()) noexcept
        : name(n), tags(t)
    {
    }
    ::etl::string_view name;
    ::etl::string_view tags;
};

struct test_case {
    name_and_tags info;
    test_func_t func;
};

struct assertion {
    char const* expression { nullptr };
    char const* file { nullptr };
    char const* function { nullptr };
    ::etl::uint32_t line { 0 };
};

struct result_disposition {
    enum flags {
        normal = 0x01,

        continue_on_failure = 0x02, // Failures test, but execution continues
        false_test          = 0x04, // Prefix expression with !
        suppress_fail = 0x08 // Failures are reported but do not fail the test
    };
};

struct session_stats {
    ::etl::uint16_t num_test_cases { 0 };
    ::etl::uint16_t num_test_cases_failed { 0 };

    ::etl::uint16_t num_assertions { 0 };
    ::etl::uint16_t num_assertions_failed { 0 };
};

template <::etl::size_t Capacity>
using session_buffer = ::etl::array<test_case, Capacity>;

struct session {
    template <::etl::size_t Capacity>
    explicit constexpr session(
        session_buffer<Capacity>& buffer, char const* name);

    [[nodiscard]] constexpr auto name() const noexcept -> char const*;

    [[nodiscard]] constexpr auto begin() -> test_case*;
    [[nodiscard]] constexpr auto end() -> test_case*;

    [[nodiscard]] auto run_all() -> int;

    constexpr auto add_test(name_and_tags const& spec, test_func_t func)
        -> void;

private:
    char const* name_ = nullptr;

    test_case* first_    = nullptr;
    test_case* last_     = nullptr;
    ::etl::size_t count_ = 0;
};

struct auto_reg {
    explicit auto_reg(session& s, name_and_tags const& sp, test_func_t func)
    {
        s.add_test(sp, func);
    }
};

struct context {
    explicit context(session& s) : session_ { s }
    {
        ::etl::ignore_unused(session_);
    }

    auto current_test(test_case* tc) -> void;

    auto pass_assertion(assertion const& payload) -> void;
    auto fail_assertion(assertion const& payload, bool terminate) -> void;

    auto terminate() -> bool;

    auto stats() const -> session_stats const& { return stats_; }

private:
    session& session_;
    test_case* current_ { nullptr };
    bool shouldTerminate_ { false };
    session_stats stats_ {};
};

}

namespace etl::test {
template <::etl::size_t Capacity>
inline constexpr session::session(
    session_buffer<Capacity>& buffer, char const* name)
    : name_ { name }, first_ { buffer.begin() }, last_ { buffer.end() }
{
}

inline constexpr auto session::name() const noexcept -> char const*
{
    return name_;
}

inline constexpr auto session::begin() -> test_case* { return first_; }

inline constexpr auto session::end() -> test_case*
{
    return ::etl::next(first_, count_);
}

inline constexpr auto session::add_test(
    name_and_tags const& spec, test_func_t func) -> void
{
    if (first_ + count_ != last_) {
        first_[count_].info.name = spec.name;
        first_[count_].info.tags = spec.tags;
        first_[count_++].func    = func;
    }
}

inline auto session::run_all() -> int
{
    auto ctx = context { *this };
    ::printf("%-10s %-10s\n", "Run:", name_);

    for (auto& tc : (*this)) {
        if (ctx.terminate()) {
            ::printf("%-10s %-10s\n", "Skip:", tc.info.name.data());
            continue;
        }

        ctx.current_test(&tc);
        ::printf("%-10s %-10s\n", "Run:", tc.info.name.data());
        tc.func(ctx);

        if (ctx.terminate()) {
            ::printf("%-10s %-10s\n", "Fail:", tc.info.name.data());
            continue;
        }

        ::printf("%-10s %-10s\n", "Pass:", tc.info.name.data());
    }

    auto const& stats = ctx.stats();
    auto const* txt   = "%-10s %-10s - tests: %d/%d assertion: %d/%d\n";
    ::printf(txt, "Pass:", name_,
        stats.num_test_cases - stats.num_test_cases_failed,
        stats.num_test_cases,
        stats.num_assertions - stats.num_assertions_failed,
        stats.num_assertions);
    return 0;
}

inline auto context::current_test(test_case* tc) -> void
{
    ++stats_.num_test_cases;
    current_ = tc;
}

inline auto context::pass_assertion(assertion const& data) -> void
{
    ::etl::ignore_unused(this, data);
    ++stats_.num_assertions;
}
inline auto context::fail_assertion(assertion const& data, bool terminate)
    -> void
{
    constexpr static auto const* fmt = "%-10s %s:%d - %s\n";
    ::printf(fmt, "Fail:", data.file, data.line, data.expression);
    ++stats_.num_assertions_failed;
    shouldTerminate_ = terminate;
}

inline auto context::terminate() -> bool { return shouldTerminate_; }

} // namespace etl::test

#define TETL_STRINGIFY(str) #str

#define TEST_DETAIL_PAYLOAD(exp)                                               \
    ::etl::test::assertion { exp, __FILE__, TETL_FUNC_SIG, __LINE__ }

#define TEST_SESSION(name, size)                                               \
    static auto g_session_buffer = ::etl::test::session_buffer<size> {};       \
    static auto g_session = ::etl::test::session { g_session_buffer, name }

#define TEST_FILE(size) TEST_SESSION(__FILE__, size);

#define TEST_SESSION_RUN(argc, argv)                                           \
    [argc, argv] {                                                             \
        ::etl::ignore_unused(argc, argv);                                      \
        return g_session.run_all();                                            \
    }()

#define TEST_DETAIL_TEST_CASE2(tc, ...)                                        \
    static auto tc(::etl::test::context& session_context)->void;               \
    namespace {                                                                \
        auto TETL_ANONYMOUS_VAR(tc) = ::etl::test::auto_reg {                  \
            g_session,                                                         \
            ::etl::test::name_and_tags { __VA_ARGS__ },                        \
            tc,                                                                \
        };                                                                     \
    }                                                                          \
    static auto tc(::etl::test::context& session_context)->void

#define TEST_DETAIL_TEST_CASE(...)                                             \
    TEST_DETAIL_TEST_CASE2(TETL_ANONYMOUS_VAR(tc), __VA_ARGS__)

#define TEST_CASE(...) TEST_DETAIL_TEST_CASE(__VA_ARGS__)

#define TEST_DETAIL_CHECK_IMPL(expr, terminate)                                \
    if (!!(expr)) {                                                            \
        session_context.pass_assertion(                                        \
            TEST_DETAIL_PAYLOAD(TETL_STRINGIFY(expr)));                        \
    } else {                                                                   \
        session_context.fail_assertion(                                        \
            TEST_DETAIL_PAYLOAD(TETL_STRINGIFY(expr)), terminate);             \
    }

#define TEST_DETAIL_CHECK_EQUAL_IMPL(a, b, terminate)                          \
    if ((a) == (b)) {                                                          \
        session_context.pass_assertion(                                        \
            TEST_DETAIL_PAYLOAD(TETL_STRINGIFY(a == b)));                      \
    } else {                                                                   \
        session_context.fail_assertion(                                        \
            TEST_DETAIL_PAYLOAD(TETL_STRINGIFY(a == b)), terminate);           \
    }

// #define CHECK(expr) TEST_DETAIL_CHECK_IMPL(expr, false);
// #define REQUIRE(expr) TEST_DETAIL_CHECK_IMPL(expr, true);

#define CHECK_FALSE(expr) TEST_DETAIL_CHECK_IMPL(!(expr), false);
#define REQUIRE_FALSE(expr) TEST_DETAIL_CHECK_IMPL(!(expr), true);

#define CHECK_EQUAL(a, b) TEST_DETAIL_CHECK_EQUAL_IMPL(a, b, false)
#define REQUIRE_EQUAL(a, b) TEST_DETAIL_CHECK_EQUAL_IMPL(a, b, true)

#define TEST_DETAIL_ASSERT(resultDisposition, ...)                             \
    do {                                                                       \
        TEST_DETAIL_IGNORE_BUT_WARN(__VA_ARGS__);                              \
        if (!static_cast<bool>(!!(__VA_ARGS__))) {                             \
            session_context.fail_assertion(                                    \
                TEST_DETAIL_PAYLOAD(TETL_STRINGIFY(__VA_ARGS__)),              \
                resultDisposition == ::etl::test::result_disposition::normal); \
        } else {                                                               \
            session_context.pass_assertion(                                    \
                TEST_DETAIL_PAYLOAD(TETL_STRINGIFY(__VA_ARGS__)));             \
        }                                                                      \
    } while (false)

#define CHECK(...)                                                             \
    TEST_DETAIL_ASSERT(                                                        \
        ::etl::test::result_disposition::continue_on_failure, __VA_ARGS__)

#define REQUIRE(...)                                                           \
    TEST_DETAIL_ASSERT(::etl::test::result_disposition::normal, __VA_ARGS__)

#endif // ETL_EXPERIMENTAL_TESTING_TESTING_HPP
