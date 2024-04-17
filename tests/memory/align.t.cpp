// SPDX-License-Identifier: BSL-1.0

#include <etl/memory.hpp>

#include <etl/array.hpp>

#include "testing/testing.hpp"

namespace {

auto test() -> bool
{
    auto buffer = etl::array<char, 128>{};
    auto space  = buffer.size() - 1;
    auto* ptr   = static_cast<void*>(buffer.data() + 1);
    CHECK(etl::align(32, 32, ptr, space) != nullptr);
    CHECK(etl::align(32, buffer.size() * 2, ptr, space) == nullptr);
    return true;
}

} // namespace

auto main() -> int
{
    CHECK(test());
    return 0;
}
