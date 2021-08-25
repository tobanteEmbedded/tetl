/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef ETL_EXPERIMENTAL_TESTING_NAME_AND_TAGS_HPP
#define ETL_EXPERIMENTAL_TESTING_NAME_AND_TAGS_HPP

#include "etl/string_view.hpp"

namespace etl::test {

struct name_and_tags {
    name_and_tags(etl::string_view const& n = etl::string_view(),
        etl::string_view const& t           = etl::string_view()) noexcept
        : name(n), tags(t)
    {
    }
    etl::string_view name;
    etl::string_view tags;
};

} // namespace etl::test

#endif // ETL_EXPERIMENTAL_TESTING_NAME_AND_TAGS_HPP
