/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/type_traits.hpp"

#include "etl/cstdint.hpp"     // for uint16_t
#include "etl/type_traits.hpp" // for enable_if

template <typename T>
auto func(T val) ->
    typename etl::enable_if<etl::is_integral<T>::value, int>::type
{
    return static_cast<int>(val);
}

auto func(float val) -> float { return val; }

auto main() -> int
{
    func(42);                  // Calls template
    func(etl::uint16_t { 1 }); // Calls template
    func(3.0F);                // Does not call template
    return 0;
}
