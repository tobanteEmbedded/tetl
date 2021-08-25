/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

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
