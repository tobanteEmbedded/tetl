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

#ifndef ETL_EXPERIMENTAL_TESTING_SESSION_HPP
#define ETL_EXPERIMENTAL_TESTING_SESSION_HPP

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/experimental/testing/name_and_tags.hpp"
#include "etl/experimental/testing/test_case.hpp"

#include <stdio.h>

namespace etl::test {

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

inline auto current_session() -> session&
{
    static auto buffer      = ::etl::test::session_buffer<16> {};
    static auto testSession = ::etl::test::session { buffer, "foo" };
    return testSession;
}

} // namespace etl::test

// #define TEST_DETAIL_SESSION(name, size)                                        \
//     static auto g_session_buffer = ::etl::test::session_buffer<size> {};       \
//     static auto g_session = ::etl::test::session { g_session_buffer, name }
// #define TEST_SESSION(name, size)        TEST_DETAIL_SESSION(name, size)

#endif // ETL_EXPERIMENTAL_TESTING_SESSION_HPP
