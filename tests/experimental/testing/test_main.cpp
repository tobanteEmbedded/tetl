// SPDX-License-Identifier: BSL-1.0

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
