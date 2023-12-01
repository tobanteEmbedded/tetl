// SPDX-License-Identifier: BSL-1.0

#include "etl/functional.hpp"

#include "etl/cstdint.hpp"
#include "etl/string_view.hpp"
#include "etl/type_traits.hpp"

#include "testing/testing.hpp"

using namespace etl::string_view_literals;

template <typename T>
auto test() -> bool
{
    using func_t = etl::inplace_function<T(T), sizeof(void*) * 2U>;

    assert(!static_cast<bool>(etl::inplace_function<T(T)> {}));
    assert(!static_cast<bool>(etl::inplace_function<T(T)> {nullptr}));

    auto func = func_t {[](T x) { return x + T(1); }};
    assert(static_cast<bool>(func));
    assert(func != nullptr);
    assert(nullptr != func);
    assert(!(func == nullptr));
    assert(!(nullptr == func));
    assert(func(T(41)) == T(42));
    assert(etl::invoke(func, T(41)) == T(42));

    auto other = func_t {};
    assert(other == nullptr);
    assert(!static_cast<bool>(other));
    func.swap(other);
    assert(static_cast<bool>(other));
    assert(!static_cast<bool>(func));
    assert(other(T(41)) == T(42));
    assert(etl::invoke(other, T(41)) == T(42));

    swap(other, func);
    assert(static_cast<bool>(func));
    assert(!static_cast<bool>(other));
    assert(func(T(41)) == T(42));
    assert(etl::invoke(func, T(41)) == T(42));

    auto copy = func;
    assert(static_cast<bool>(func));
    assert(static_cast<bool>(copy));
    assert(copy(T(41)) == T(42));

    auto emptyCopy = other;
    assert(!static_cast<bool>(emptyCopy));
    assert(!static_cast<bool>(other));

    copy = nullptr;
    assert(!static_cast<bool>(copy));

    copy = etl::move(func);
    assert(static_cast<bool>(copy));

    using small_func_t = etl::inplace_function<T(T), sizeof(void*)>;
    auto small         = small_func_t {[](T x) { return x + T(2); }};
    copy               = small;
    assert(static_cast<bool>(copy));
    assert(copy(T(1)) == T(3));

    auto move = func_t {};
    move      = etl::move(small);
    assert(static_cast<bool>(move));
    assert(move(T(1)) == T(3));

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

static auto test_all() -> bool
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
