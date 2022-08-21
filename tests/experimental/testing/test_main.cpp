/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/experimental/testing/testing.hpp"
#include "etl/warning.hpp"

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)

auto main(int argc, char const** argv) -> int
{
    etl::ignore_unused(argc, argv);
    return etl::test::current_session().run_all();
}
#else
auto main() -> int { return 0; }
#endif
