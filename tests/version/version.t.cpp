// SPDX-License-Identifier: BSL-1.0

#include <etl/version.hpp>

#include "testing/testing.hpp"

constexpr auto test() -> bool
{
    CHECK(etl::language_standard::cpp_17 == etl::language_standard::cpp_17);
    CHECK(etl::language_standard::cpp_20 == etl::language_standard::cpp_20);
    CHECK(etl::language_standard::cpp_23 == etl::language_standard::cpp_23);
    CHECK(etl::language_standard::cpp_26 == etl::language_standard::cpp_26);

    CHECK(etl::language_standard::cpp_17 < etl::language_standard::cpp_20);
    CHECK(etl::language_standard::cpp_17 < etl::language_standard::cpp_23);
    CHECK(etl::language_standard::cpp_17 < etl::language_standard::cpp_26);

    CHECK(etl::language_standard::cpp_20 > etl::language_standard::cpp_17);
    CHECK(etl::language_standard::cpp_23 > etl::language_standard::cpp_17);

#if TETL_CPP_STANDARD == 17
    CHECK(etl::current_standard == etl::language_standard::cpp_17);
#endif

#if TETL_CPP_STANDARD == 20
    CHECK(etl::current_standard == etl::language_standard::cpp_20);
#endif

#if TETL_CPP_STANDARD == 23
    CHECK(etl::current_standard == etl::language_standard::cpp_23);
#endif

#if TETL_CPP_STANDARD == 26
    CHECK(etl::current_standard == etl::language_standard::cpp_26);
#endif

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test());
    return 0;
}
