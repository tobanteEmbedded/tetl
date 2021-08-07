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

#include <stdio.h>

namespace etl::test {

struct context;

using tc_function_t = void (*)(context&);

struct tc_spec {
    char const* name { nullptr };
    char const* tags { nullptr };
};

struct test_case : tc_spec {
    tc_function_t func;
};

template <::etl::size_t Capacity>
using session_buffer = ::etl::array<test_case, Capacity>;

struct session {
    template <::etl::size_t Capacity>
    explicit session(session_buffer<Capacity>& buffer, char const* name);

    [[nodiscard]] auto name() const noexcept -> char const*;

    [[nodiscard]] auto begin() -> test_case*;
    [[nodiscard]] auto end() -> test_case*;

    auto add_test(tc_spec const& spec, tc_function_t func) -> void;
    [[nodiscard]] auto run_all() -> int;

private:
    char const* name_ = nullptr;

    test_case* first_    = nullptr;
    test_case* last_     = nullptr;
    ::etl::size_t count_ = 0;
};

struct context {
    explicit context(session& s) : session_ { s } { }

    auto current_test(tc_spec* tc) -> void { current_ = tc; }

    auto pass_assertion() -> void;
    auto fail_assertion(bool terminate) -> void;

    auto terminate() -> bool;

private:
    session& session_;
    tc_spec* current_ { nullptr };
    bool shouldTerminate_ { false };
};

}

namespace etl::test {
template <::etl::size_t Capacity>
inline session::session(session_buffer<Capacity>& buffer, char const* name)
    : name_ { name }, first_ { buffer.begin() }, last_ { buffer.end() }
{
}

inline auto session::name() const noexcept -> char const* { return name_; }

inline auto session::begin() -> test_case* { return first_; }

inline auto session::end() -> test_case* { return ::etl::next(first_, count_); }

inline auto session::add_test(tc_spec const& spec, tc_function_t func) -> void
{
    if (first_ + count_ != last_) {
        first_[count_].name   = spec.name;
        first_[count_].tags   = spec.tags;
        first_[count_++].func = func;
    }
}

inline auto session::run_all() -> int
{
    auto ctx = context { *this };
    for (auto& tc : (*this)) {
        ctx.current_test(&tc);
        ::printf("Running test: %s\n", tc.name);
        tc.func(ctx);
        if (ctx.terminate()) { return 1; }
        ::printf("Running test: %s - done!\n", tc.name);
    }

    return 0;
}

inline auto context::pass_assertion() -> void { ::puts("pass_assertion"); }
inline auto context::fail_assertion(bool terminate) -> void
{
    ::puts("fail_assertion");
    shouldTerminate_ = terminate;
}
inline auto context::terminate() -> bool { return shouldTerminate_; }

} // namespace etl::test

#define TEST_SESSION(name, size)                                               \
    static auto g_session_buffer = ::etl::test::session_buffer<size> {};       \
    static auto g_session = ::etl::test::session { g_session_buffer, name }

#define TEST_SESSION_RUN(argc, argv) g_session.run_all()

#define TEST_CASE_IMPL(n, t, test_case_type)                                   \
    struct test_case_type {                                                    \
        test_case_type(                                                        \
            ::etl::test::session& s, ::etl::test::tc_spec const& sp)           \
        {                                                                      \
            s.add_test(sp, [](::etl::test::context& ctx) { run(ctx); });       \
        }                                                                      \
        static auto run(::etl::test::context&) -> void;                        \
    };                                                                         \
                                                                               \
    static auto TETL_ANONYMOUS_VAR(tc) = test_case_type {                      \
        g_session,                                                             \
        ::etl::test::tc_spec {                                                 \
            /*.name = */ n,                                                    \
            /* .tags = */ t,                                                   \
        },                                                                     \
    };                                                                         \
                                                                               \
    auto test_case_type::run(::etl::test::context& session_context)->void

#define TEST_CASE(name, tags) TEST_CASE_IMPL(name, tags, TETL_ANONYMOUS_VAR(tc))

#define CHECK_IMPL(expr, terminate)                                            \
    if (!!(expr)) {                                                            \
        session_context.pass_assertion();                                      \
    } else {                                                                   \
        session_context.fail_assertion(terminate);                             \
    }

#define CHECK_EQUAL_IMPL(a, b, terminate)                                      \
    if ((a) == (b)) {                                                          \
        session_context.pass_assertion();                                      \
    } else {                                                                   \
        session_context.fail_assertion(terminate);                             \
    }

#define CHECK(expr) CHECK_IMPL(expr, false);
#define REQUIRE(expr) CHECK_IMPL(expr, true);

#define CHECK_FALSE(expr) CHECK_IMPL(!(expr), false);
#define REQUIRE_FALSE(expr) CHECK_IMPL(!(expr), true);

#define CHECK_EQUAL(a, b) CHECK_EQUAL_IMPL(a, b, false)
#define REQUIRE_EQUAL(a, b) CHECK_EQUAL_IMPL(a, b, true)

#endif // ETL_EXPERIMENTAL_TESTING_TESTING_HPP
