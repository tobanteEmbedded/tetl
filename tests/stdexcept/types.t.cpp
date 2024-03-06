// SPDX-License-Identifier: BSL-1.0

#include <etl/stdexcept.hpp>

#include <etl/exception.hpp>
#include <etl/type_traits.hpp>

#include "testing/exception.hpp"
#include "testing/testing.hpp"

constexpr auto test() -> bool
{
    TEST_EXCEPTION(etl::logic_error, etl::exception);
    TEST_EXCEPTION(etl::domain_error, etl::logic_error);
    TEST_EXCEPTION(etl::invalid_argument, etl::logic_error);
    TEST_EXCEPTION(etl::length_error, etl::logic_error);
    TEST_EXCEPTION(etl::out_of_range, etl::logic_error);

    TEST_EXCEPTION(etl::runtime_error, etl::exception);
    TEST_EXCEPTION(etl::range_error, etl::runtime_error);
    TEST_EXCEPTION(etl::overflow_error, etl::runtime_error);
    TEST_EXCEPTION(etl::underflow_error, etl::runtime_error);

    return true;
}

auto main() -> int
{
    assert(test());
    static_assert(test());
    return 0;
}
