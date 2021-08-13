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

#ifndef ETL_EXPERIMENTAL_TESTING_SECTION_HPP
#define ETL_EXPERIMENTAL_TESTING_SECTION_HPP

#include "etl/experimental/testing/source_line_info.hpp"
#include "etl/experimental/testing/totals.hpp"

#include "etl/string_view.hpp"
#include "etl/utility.hpp"

namespace etl::test {

struct section_info {
    constexpr section_info(source_line_info const& sli, etl::string_view n)
        : name(n), line_info(sli)
    {
    }

    etl::string_view name;
    source_line_info line_info;
};

struct section {
    explicit section(section_info const& info, bool shouldExecute)
        : info_ { info }, shouldExecute_ { shouldExecute }
    {
    }

    [[nodiscard]] constexpr auto info() const noexcept -> section_info const&
    {
        return info_;
    }

    explicit operator bool() const noexcept { return shouldExecute_; }

private:
    section_info info_;
    counts assertions_ {};
    bool shouldExecute_;
};

} // namespace etl::test

#endif // ETL_EXPERIMENTAL_TESTING_SECTION_HPP
