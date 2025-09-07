// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2025 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/system_error.hpp>
    #include <etl/type_traits.hpp>
#endif

static constexpr auto test_all() -> bool
{
    CHECK(etl::is_scoped_enum_v<etl::errc>);
    CHECK(etl::is_error_condition_enum_v<etl::errc>);
    CHECK(sizeof(etl::errc) == sizeof(unsigned char));

    // default construction should be equal to the first named enumeration
    CHECK(etl::errc{} != etl::errc::address_family_not_supported);

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
