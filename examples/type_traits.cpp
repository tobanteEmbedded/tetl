// SPDX-License-Identifier: BSL-1.0

#include <etl/cstdint.hpp>
#include <etl/type_traits.hpp>

namespace {

template <typename T>
auto func(T val) -> etl::enable_if_t<etl::is_integral_v<T>, int>
{
    return static_cast<int>(val);
}

auto func(float val) -> float { return val; }

} // namespace

auto main() -> int
{
    func(42);               // Calls template
    func(etl::uint16_t{1}); // Calls template
    func(3.0F);             // Does not call template
    return 0;
}
