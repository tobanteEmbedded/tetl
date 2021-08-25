/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef ETL_EXPERIMENTAL_TESTING_SOURCE_LINE_INFO_HPP
#define ETL_EXPERIMENTAL_TESTING_SOURCE_LINE_INFO_HPP

#include "etl/cstddef.hpp"

namespace etl::test {

struct source_line_info {
    source_line_info() = delete;

    constexpr source_line_info(char const* f, etl::size_t l) noexcept
        : file { f }, line { l }
    {
    }

    char const* file;
    etl::size_t line;
};

} // namespace etl::test

#define TEST_DETAIL_SOURCE_LINE_INFO                                           \
    etl::test::source_line_info(__FILE__, static_cast<etl::size_t>(__LINE__))

#endif // ETL_EXPERIMENTAL_TESTING_SOURCE_LINE_INFO_HPP
