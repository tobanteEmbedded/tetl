
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
