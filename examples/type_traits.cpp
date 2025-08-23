// SPDX-License-Identifier: BSL-1.0

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/cstdint.hpp>
    #include <etl/type_traits.hpp>
#endif

namespace {

template <typename T>
    requires(etl::is_integral_v<T>)
auto func(T val) -> int
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
