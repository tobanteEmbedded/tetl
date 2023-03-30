// SPDX-License-Identifier: BSL-1.0

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
