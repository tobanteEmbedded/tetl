/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef ETL_EXPERIMENTAL_TESTING_TEST_CASE_HPP
#define ETL_EXPERIMENTAL_TESTING_TEST_CASE_HPP

#include "etl/experimental/testing/name_and_tags.hpp"

namespace etl::test {

using test_func_t = void (*)();

struct test_case {
    name_and_tags info;
    test_func_t func;
    etl::string_view type_name {};
};

} // namespace etl::test

#endif // ETL_EXPERIMENTAL_TESTING_TEST_CASE_HPP
