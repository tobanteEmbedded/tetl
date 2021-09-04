/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/functional.hpp"

#include "etl/cstdint.hpp"
#include "etl/string_view.hpp"
#include "etl/type_traits.hpp"

#include "testing.hpp"

using namespace etl::string_view_literals;

template <typename T>
auto test() -> bool
{
    using func_t = etl::inplace_function<T(T)>;

    auto func = func_t { [](T x) { return x + T(1); } };

    assert(static_cast<bool>(func));
    assert(!static_cast<bool>(etl::inplace_function<T(T)> {}));
    assert(!static_cast<bool>(etl::inplace_function<T(T)> { nullptr }));

    assert(func(T(41)) == T(42));
    assert(etl::invoke(func, T(41)) == T(42));

#if defined(__cpp_exceptions)
    try {
        auto empty = func_t {};
        empty(T {});
        assert(false);
    } catch (etl::bad_function_call const& e) {
        assert(e.what() == "empty inplace_func_vtable"_sv);
    } catch (...) { // NOLINT
        assert(false);
    }
#endif
    return true;
}

auto test_all() -> bool
{
    assert(test<etl::int8_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::int64_t>());
    assert(test<etl::uint8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::uint64_t>());
    assert(test<float>());
    assert(test<double>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    return 0;
}