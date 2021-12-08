/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef ETL_EXPERIMENTAL_TESTING_SESSION_HPP
#define ETL_EXPERIMENTAL_TESTING_SESSION_HPP

#include "etl/experimental/testing/name_and_tags.hpp"
#include "etl/experimental/testing/source_line_info.hpp"
#include "etl/experimental/testing/test_case.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"
#include "etl/stack.hpp"
#include "etl/string_view.hpp"
#include "etl/vector.hpp"

#include <stdio.h>

namespace etl::test {

struct session_stats {
    etl::uint16_t num_test_cases { 0 };
    etl::uint16_t num_test_cases_failed { 0 };

    etl::uint16_t num_assertions { 0 };
    etl::uint16_t num_assertions_failed { 0 };
};

template <etl::size_t Capacity>
using session_buffer = etl::array<test_case, Capacity>;

struct session {
    template <etl::size_t Capacity>
    explicit constexpr session(session_buffer<Capacity>& buffer, etl::string_view name);

    [[nodiscard]] constexpr auto name() const noexcept -> etl::string_view;

    [[nodiscard]] constexpr auto begin() -> test_case*;
    [[nodiscard]] constexpr auto end() -> test_case*;

    [[nodiscard]] auto run_all() -> int;

    constexpr auto add_test(name_and_tags const& spec, test_func_t func, etl::string_view typeName = {}) -> void;

    auto current_test(test_case* tc) -> void;

    auto pass_assertion(source_line_info const& src, char const* expr) -> void;
    auto fail_assertion(source_line_info const& src, char const* expr, bool terminate) -> void;

    [[nodiscard]] auto terminate() const -> bool;

    [[nodiscard]] auto stats() const -> session_stats const& { return stats_; }

private:
    // using section_stack_t
    //  = etl::stack<etl::string_view, etl::static_vector<etl::string_view, 2>>;
    etl::string_view name_;

    test_case* first_  = nullptr;
    test_case* last_   = nullptr;
    etl::size_t count_ = 0;

    test_case* current_ { nullptr };
    // section_stack_t sections_ {};
    bool shouldTerminate_ { false };
    session_stats stats_ {};
};

inline auto current_session() -> session&;

template <etl::size_t Capacity>
inline constexpr session::session(session_buffer<Capacity>& buffer, etl::string_view name)
    : name_ { name }, first_ { buffer.begin() }, last_ { buffer.end() }
{
}

inline constexpr auto session::name() const noexcept -> etl::string_view { return name_; }

inline constexpr auto session::begin() -> test_case* { return first_; }

inline constexpr auto session::end() -> test_case* { return etl::next(first_, static_cast<etl::ptrdiff_t>(count_)); }

inline constexpr auto session::add_test(name_and_tags const& spec, test_func_t func, etl::string_view typeName) -> void
{
    if (first_ + count_ != last_) {
        first_[count_].info.name = spec.name;
        first_[count_].info.tags = spec.tags;
        first_[count_].type_name = typeName;
        first_[count_++].func    = func;
    }
}

inline auto session::run_all() -> int
{
    ::printf("%-10s %-10s\n", "Run:", name_.data());

    for (auto& tc : (*this)) {
        if (terminate()) {
            ::printf(
                "%-10s %-10s %-10s\n", "Skip:", tc.info.name.data(), tc.type_name.empty() ? "" : tc.type_name.data());
            continue;
        }

        current_test(&tc);
        ::printf("%-10s %-10s %-10s\n", "Run:", tc.info.name.data(), tc.type_name.empty() ? "" : tc.type_name.data());
        tc.func();

        if (terminate()) {
            ::printf("%-10s %-10s\n", "Fail:", tc.info.name.data());
            continue;
        }

        ::printf("%-10s %-10s\n", "Pass:", tc.info.name.data());
    }

    auto const& s   = stats();
    auto const* txt = "\nAll tests passed (%d assertions in %d test cases)\n";
    ::printf(txt, s.num_assertions, s.num_test_cases);
    return 0;
}

inline auto session::current_test(test_case* tc) -> void
{
    ++stats_.num_test_cases;
    current_ = tc;
}

inline auto session::pass_assertion(source_line_info const& src, char const* expr) -> void
{
    etl::ignore_unused(this, src, expr);
    ++stats_.num_assertions;
}

inline auto session::fail_assertion(source_line_info const& src, char const* expr, bool terminate) -> void
{
    constexpr static auto const* fmt = "%-10s %s:%d - %s\n";
    ::printf(fmt, "Fail:", src.file, static_cast<int>(src.line), expr);
    ++stats_.num_assertions_failed;
    shouldTerminate_ = terminate;
}

inline auto session::terminate() const -> bool { return shouldTerminate_; }

inline auto current_session() -> session&
{
    static auto buffer      = etl::test::session_buffer<128> {};
    static auto testSession = etl::test::session { buffer, "DUMMY SESSION" };
    return testSession;
}

struct auto_reg {
    explicit auto_reg(name_and_tags const& sp, test_func_t func) { current_session().add_test(sp, func); }
};

} // namespace etl::test

#endif // ETL_EXPERIMENTAL_TESTING_SESSION_HPP
