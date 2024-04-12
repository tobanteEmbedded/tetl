// SPDX-License-Identifier: BSL-1.0

#include <etl/memory.hpp>

#include <etl/array.hpp>

#include "testing/testing.hpp"

#if defined(__cpp_exceptions)
namespace {

bool moveWasCalled = false;

struct ThrowOnMove {
    ThrowOnMove()  = default;
    ~ThrowOnMove() = default;

    auto operator=(ThrowOnMove const& other) -> ThrowOnMove& = default;
    auto operator=(ThrowOnMove&& other) -> ThrowOnMove&      = default;

    ThrowOnMove(ThrowOnMove const& other) = default;
    ThrowOnMove(ThrowOnMove&& /*other*/)
    {
        moveWasCalled = true;
        throw 1; // NOLINT
    }
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
