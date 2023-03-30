// SPDX-License-Identifier: BSL-1.0

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
