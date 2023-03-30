// SPDX-License-Identifier: BSL-1.0

#ifndef ETL_EXPERIMENTAL_TESTING_ASSERTION_HANDLER_HPP
#define ETL_EXPERIMENTAL_TESTING_ASSERTION_HANDLER_HPP

#include "etl/experimental/testing/result_disposition.hpp"
#include "etl/experimental/testing/session.hpp"
#include "etl/experimental/testing/source_line_info.hpp"

namespace etl::test {

struct assertion_handler {
    assertion_handler(source_line_info const& src, result_disposition::flags flags, char const* expr, bool result)
        : src_ { src }
        , flags_ { flags }
        , expr_ { expr }
        , res_ { has_flag(result_disposition::false_test) ? !result : result }
    {
        if (res_ || has_flag(result_disposition::suppress_fail)) { current_session().pass_assertion(src_, expr_); }
        if (!res_ && has_flag(result_disposition::normal)) { current_session().fail_assertion(src_, expr_, true); }
        if (!res_ && has_flag(result_disposition::continue_on_failure)) {
            current_session().fail_assertion(src_, expr_, false);
        }
    }

private:
    [[nodiscard]] auto has_flag(result_disposition::flags flag) -> bool { return (flags_ & flag) != 0; }

    source_line_info src_;
    result_disposition::flags flags_;
    char const* expr_;
    bool res_;
};

} // namespace etl::test

#endif // ETL_EXPERIMENTAL_TESTING_ASSERTION_HANDLER_HPP
