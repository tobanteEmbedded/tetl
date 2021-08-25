/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef ETL_EXPERIMENTAL_TESTING_RESULT_DUSPOSITION_HPP
#define ETL_EXPERIMENTAL_TESTING_RESULT_DUSPOSITION_HPP

namespace etl::test {

struct result_disposition {
    enum flags : unsigned char {
        normal              = 0x01,
        continue_on_failure = 0x02, // Failures test, but execution continues
        false_test          = 0x04, // Prefix expression with !
        suppress_fail       = 0x08  // Failures do not fail the test
    };
};

} // namespace etl::test

#endif // ETL_EXPERIMENTAL_TESTING_RESULT_DUSPOSITION_HPP
