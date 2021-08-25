/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/cwchar.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEST_CASE("cwchar: NULL", "[cwchar]")
{
    // NOLINTNEXTLINE(modernize-use-nullptr)
    CHECK(static_cast<decltype(nullptr)>(NULL) == nullptr);
}