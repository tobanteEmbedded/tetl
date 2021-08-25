
/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef ETL_EXPERIMENTAL_TESTING_TOTALS_HPP
#define ETL_EXPERIMENTAL_TESTING_TOTALS_HPP

#include "etl/cstdint.hpp"

namespace etl::test {

struct counts {
    constexpr auto operator-(counts const& other) const -> counts;
    constexpr auto operator+=(counts const& other) -> counts&;

    [[nodiscard]] constexpr auto total() const -> etl::uint16_t;
    [[nodiscard]] constexpr auto all_passed() const -> bool;
    [[nodiscard]] constexpr auto all_ok() const -> bool;

    etl::uint16_t passed { 0 };
    etl::uint16_t failed { 0 };
    etl::uint16_t failed_but_ok { 0 };
};

struct totals {
    constexpr auto operator-(totals const& other) const -> totals;
    constexpr auto operator+=(totals const& other) -> totals&;

    [[nodiscard]] constexpr auto delta(totals const& prevtotals) const
        -> totals;

    int error { 0 };
    counts assertions {};
    counts test_cases {};
};

constexpr auto counts::operator-(counts const& other) const -> counts
{
    auto diff          = counts {};
    diff.passed        = passed - other.passed;
    diff.failed        = failed - other.failed;
    diff.failed_but_ok = failed_but_ok - other.failed_but_ok;
    return diff;
}

constexpr auto counts::operator+=(counts const& other) -> counts&
{
    passed += other.passed;
    failed += other.failed;
    failed_but_ok += other.failed_but_ok;
    return *this;
}

constexpr auto counts::total() const -> etl::uint16_t
{
    return passed + failed + failed_but_ok;
}
constexpr auto counts::all_passed() const -> bool
{
    return failed == 0 && failed_but_ok == 0;
}

constexpr auto counts::all_ok() const -> bool { return failed == 0; }

constexpr auto totals::operator-(totals const& other) const -> totals
{
    auto diff       = totals {};
    diff.assertions = assertions - other.assertions;
    diff.test_cases = test_cases - other.test_cases;
    return diff;
}

constexpr auto totals::operator+=(totals const& other) -> totals&
{
    assertions += other.assertions;
    test_cases += other.test_cases;
    return *this;
}

constexpr auto totals::delta(totals const& prevtotals) const -> totals
{
    auto diff = *this - prevtotals;
    if (diff.assertions.failed > 0) {
        ++diff.test_cases.failed;
    } else if (diff.assertions.failed_but_ok > 0) {
        ++diff.test_cases.failed_but_ok;
    } else {
        ++diff.test_cases.passed;
    }
    return diff;
}

} // namespace etl::test

#endif // ETL_EXPERIMENTAL_TESTING_TOTALS_HPP
