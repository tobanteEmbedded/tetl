// SPDX-License-Identifier: BSL-1.0

#include <etl/version.hpp>

#include "testing/testing.hpp"

constexpr auto test() -> bool
{
    using etl::language_standard;

    assert(language_standard::cpp_17 == language_standard::cpp_17);
    assert(language_standard::cpp_20 == language_standard::cpp_20);
    assert(language_standard::cpp_23 == language_standard::cpp_23);
    assert(language_standard::cpp_26 == language_standard::cpp_26);

    assert(language_standard::cpp_17 < language_standard::cpp_20);
    assert(language_standard::cpp_17 < language_standard::cpp_23);
    assert(language_standard::cpp_17 < language_standard::cpp_26);

    assert(language_standard::cpp_20 > language_standard::cpp_17);
    assert(language_standard::cpp_23 > language_standard::cpp_17);

#if TETL_CPP_STANDARD == 17
    assert(etl::current_standard == language_standard::cpp_17);
#endif

#if TETL_CPP_STANDARD == 20
    assert(etl::current_standard == language_standard::cpp_20);
#endif

#if TETL_CPP_STANDARD == 23
    assert(etl::current_standard == language_standard::cpp_23);
#endif

#if TETL_CPP_STANDARD == 26
    assert(etl::current_standard == language_standard::cpp_26);
#endif

    return true;
}

auto main() -> int
{
    assert(test());
    static_assert(test());
    return 0;
}
