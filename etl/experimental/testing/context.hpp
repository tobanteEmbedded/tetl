

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

#ifndef ETL_EXPERIMENTAL_TESTING_CONTEXT_HPP
#define ETL_EXPERIMENTAL_TESTING_CONTEXT_HPP

#include "etl/experimental/testing/session.hpp"
#include "etl/experimental/testing/source_line_info.hpp"
#include "etl/experimental/testing/test_case.hpp"

namespace etl::test {

struct context {
    explicit context(session& s) : session_ { s }
    {
        ::etl::ignore_unused(session_);
    }

    auto current_test(test_case* tc) -> void;

    auto pass_assertion(source_line_info const& src, char const* expr) -> void;
    auto fail_assertion(
        source_line_info const& src, char const* expr, bool terminate) -> void;

    [[nodiscard]] auto terminate() const -> bool;

    [[nodiscard]] auto stats() const -> session_stats const& { return stats_; }

private:
    session& session_;
    test_case* current_ { nullptr };
    bool shouldTerminate_ { false };
    session_stats stats_ {};
};

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
    return ::etl::next(first_, static_cast<::etl::ptrdiff_t>(count_));
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
    auto const* txt   = "\nAll tests passed (%d assertions in %d test cases)\n";
    ::printf(txt, stats.num_assertions, stats.num_test_cases);
    return 0;
}

inline auto context::current_test(test_case* tc) -> void
{
    ++stats_.num_test_cases;
    current_ = tc;
}

inline auto context::pass_assertion(
    source_line_info const& src, char const* expr) -> void
{
    ::etl::ignore_unused(this, src, expr);
    ++stats_.num_assertions;
}

inline auto context::fail_assertion(
    source_line_info const& src, char const* expr, bool terminate) -> void
{
    constexpr static auto const* fmt = "%-10s %s:%d - %s\n";
    ::printf(fmt, "Fail:", src.file, static_cast<int>(src.line), expr);
    ++stats_.num_assertions_failed;
    shouldTerminate_ = terminate;
}

inline auto context::terminate() const -> bool { return shouldTerminate_; }

} // namespace etl::test

#endif // ETL_EXPERIMENTAL_TESTING_CONTEXT_HPP
