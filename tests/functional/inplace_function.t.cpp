// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/cstdint.hpp>
    #include <etl/functional.hpp>
    #include <etl/string_view.hpp>
    #include <etl/type_traits.hpp>
    #include <etl/utility.hpp>
#endif

using namespace etl::string_view_literals;

template <typename T>
static auto test() -> bool
{
    using func_t = etl::inplace_function<T(T), sizeof(void*) * 2U>;

    CHECK_FALSE(static_cast<bool>(etl::inplace_function<T(T)>{}));
    CHECK_FALSE(static_cast<bool>(etl::inplace_function<T(T)>{nullptr}));

    auto func = func_t{[](T x) -> T { return static_cast<T>(x + T(1)); }};
    CHECK(static_cast<bool>(func));
    CHECK(func != nullptr);
    CHECK(nullptr != func);
    CHECK_FALSE(func == nullptr);
    CHECK_FALSE(nullptr == func);
    CHECK(func(T(41)) == T(42));
    CHECK(etl::invoke(func, T(41)) == T(42));

    auto other = func_t{};
    CHECK(other == nullptr);
    CHECK_FALSE(static_cast<bool>(other));
    func.swap(other);
    CHECK(static_cast<bool>(other));
    CHECK_FALSE(static_cast<bool>(func));
    CHECK(other(T(41)) == T(42));
    CHECK(etl::invoke(other, T(41)) == T(42));

    swap(other, func);
    CHECK(static_cast<bool>(func));
    CHECK_FALSE(static_cast<bool>(other));
    CHECK(func(T(41)) == T(42));
    CHECK(etl::invoke(func, T(41)) == T(42));

    auto copy = func;
    CHECK(static_cast<bool>(func));
    CHECK(static_cast<bool>(copy));
    CHECK(copy(T(41)) == T(42));

    auto emptyCopy = other;
    CHECK_FALSE(static_cast<bool>(emptyCopy));
    CHECK_FALSE(static_cast<bool>(other));

    copy = nullptr;
    CHECK_FALSE(static_cast<bool>(copy));

    copy = etl::move(func);
    CHECK(static_cast<bool>(copy));

    using small_func_t = etl::inplace_function<T(T), sizeof(void*)>;
    auto small         = small_func_t{[](T x) -> T { return x + T(2); }};
    copy               = small;
    CHECK(static_cast<bool>(copy));
    CHECK(copy(T(1)) == T(3));

    auto move = func_t{};
    move      = etl::move(small);
    CHECK(static_cast<bool>(move));
    CHECK(move(T(1)) == T(3));

    // TODO: Somehow enable user config file when using modules
#if not defined(TETL_ENABLE_CXX_MODULES)
    #if defined(__cpp_exceptions)
    auto threw = false;
    try {
        auto empty = func_t{};
        empty(T{});
    } catch (etl::bad_function_call const& e) {
        threw = true;
        CHECK(e.what() == "empty inplace_func_vtable"_sv);
    }
    CHECK(threw);
    #endif
#endif
    return true;
}

static auto test_all() -> bool
{
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::int64_t>());
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<float>());
    CHECK(test<double>());

    return true;
}

auto main() -> int
{
    CHECK(test_all());
    return 0;
}
