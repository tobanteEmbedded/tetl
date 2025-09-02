// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/memory.hpp>
#endif

#if defined(__cpp_exceptions)
namespace {

bool moveWasCalled = false;

struct ThrowOnMove {
    ThrowOnMove(int i = 0)
        : val{i}
    {
    }
    ~ThrowOnMove() = default;

    auto operator=(ThrowOnMove const& other) -> ThrowOnMove& = default;
    auto operator=(ThrowOnMove&& other) -> ThrowOnMove&      = default;

    ThrowOnMove(ThrowOnMove const& other) = default;
    ThrowOnMove(ThrowOnMove&& other)
    {
        moveWasCalled = true;
        if (other.val == 0) {
            throw 1; // NOLINT
        }
    }

    int val;
};

auto test() -> bool
{
    try {
        auto src  = etl::array<ThrowOnMove, 2>{};
        auto dest = etl::uninitialized_array<ThrowOnMove, 2>{};
        CHECK_FALSE(moveWasCalled);
        etl::uninitialized_move(src.begin(), src.end(), dest.data());
    } catch (int e) { // NOLINT
        CHECK(e == 1);
    }

    CHECK(moveWasCalled);
    return true;
}

} // namespace

auto main() -> int
{
    CHECK(test());
    return 0;
}
#else
auto main() -> int { return 0; }
#endif
