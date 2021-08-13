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

#ifndef ETL_EXPERIMENTAL_TESTING_ASSERTION_HANDLER_HPP
#define ETL_EXPERIMENTAL_TESTING_ASSERTION_HANDLER_HPP

#include "etl/experimental/testing/result_disposition.hpp"
#include "etl/experimental/testing/session.hpp"
#include "etl/experimental/testing/source_line_info.hpp"

namespace etl::test {

struct assertion_handler {
    assertion_handler(source_line_info const& src,
        result_disposition::flags flags, char const* expr, bool result)
        : src_ { src }
        , flags_ { flags }
        , expr_ { expr }
        , res_ { has_flag(result_disposition::false_test) ? !result : result }
    {
        if (res_ || has_flag(result_disposition::suppress_fail)) {
            current_session().pass_assertion(src_, expr_);
        }
        if (!res_ && has_flag(result_disposition::normal)) {
            current_session().fail_assertion(src_, expr_, true);
        }
        if (!res_ && has_flag(result_disposition::continue_on_failure)) {
            current_session().fail_assertion(src_, expr_, false);
        }
    }

private:
    [[nodiscard]] auto has_flag(result_disposition::flags flag) -> bool
    {
        return (flags_ & flag) != 0;
    }

    source_line_info src_;
    result_disposition::flags flags_;
    char const* expr_;
    bool res_;
};

} // namespace etl::test

#endif // ETL_EXPERIMENTAL_TESTING_ASSERTION_HANDLER_HPP
