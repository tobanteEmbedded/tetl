/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#include "etl/cstdio.hpp"

#include "etl/cstddef.hpp"

#include "catch2/catch_template_test_macros.hpp"

TEST_CASE("cstdio: NULL", "[cstdio]")
{
    // NOLINTNEXTLINE(modernize-use-nullptr)
    CHECK(static_cast<etl::nullptr_t>(NULL) == nullptr);
}