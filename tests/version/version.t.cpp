/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/version.hpp"

#include "testing/testing.hpp"

constexpr auto test() -> bool
{
    using etl::language_standard;

    assert(language_standard::cpp_17 == language_standard::cpp_17);
    assert(language_standard::cpp_20 == language_standard::cpp_20);
    assert(language_standard::cpp_23 == language_standard::cpp_23);

    assert(language_standard::cpp_17 < language_standard::cpp_20);
    assert(language_standard::cpp_17 < language_standard::cpp_23);

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

    return true;
}

auto main() -> int
{
    assert(test());
    static_assert(test());
    return 0;
}
