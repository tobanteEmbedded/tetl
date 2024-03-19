// SPDX-License-Identifier: BSL-1.0

#include <etl/stdexcept.hpp>

#include <etl/exception.hpp>
#include <etl/type_traits.hpp>

#include "testing/exception.hpp"
#include "testing/testing.hpp"

constexpr auto test() -> bool
{
    CHECK_EXCEPTION_TYPE(etl::logic_error, etl::exception);
    CHECK_EXCEPTION_TYPE(etl::domain_error, etl::logic_error);
    CHECK_EXCEPTION_TYPE(etl::invalid_argument, etl::logic_error);
    CHECK_EXCEPTION_TYPE(etl::length_error, etl::logic_error);
    CHECK_EXCEPTION_TYPE(etl::out_of_range, etl::logic_error);

    CHECK_EXCEPTION_TYPE(etl::runtime_error, etl::exception);
    CHECK_EXCEPTION_TYPE(etl::range_error, etl::runtime_error);
    CHECK_EXCEPTION_TYPE(etl::overflow_error, etl::runtime_error);
    CHECK_EXCEPTION_TYPE(etl::underflow_error, etl::runtime_error);

    return true;
}

auto main() -> int
{
    CHECK(test());
    static_assert(test());
    return 0;
}
