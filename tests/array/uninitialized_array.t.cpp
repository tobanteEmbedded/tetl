// SPDX-License-Identifier: BSL-1.0

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/cstddef.hpp>
    #include <etl/cstdint.hpp>
    #include <etl/type_traits.hpp>
    #include <etl/utility.hpp>
#endif

namespace {

struct NonTrivial {
    NonTrivial() { } // NOLINT

    ~NonTrivial() { } // NOLINT
};

template <typename T>
constexpr auto test_trivial() -> bool
{
    CHECK(etl::is_trivially_copy_constructible_v<T>);
    CHECK(etl::is_trivially_move_constructible_v<T>);
    CHECK(etl::is_trivially_copy_assignable_v<T>);
    CHECK(etl::is_trivially_move_assignable_v<T>);
    CHECK(etl::is_trivially_destructible_v<T>);

    // Size == 0
    using Array0 = etl::uninitialized_array<T, 0>;
    CHECK(etl::is_trivially_copy_constructible_v<Array0>);
    CHECK(etl::is_trivially_move_constructible_v<Array0>);
    CHECK(etl::is_trivially_copy_assignable_v<Array0>);
    CHECK(etl::is_trivially_move_assignable_v<Array0>);
    CHECK(etl::is_trivially_destructible_v<Array0>);

    auto array0 = Array0{};
    CHECK(etl::is_empty_v<Array0>);
    CHECK(etl::is_trivial_v<Array0>);
    CHECK_SAME_TYPE(typename Array0::value_type, T);
    CHECK_SAME_TYPE(decltype(Array0::size()), etl::size_t);
    CHECK_SAME_TYPE(decltype(array0.data()), T*);
    CHECK_SAME_TYPE(decltype(etl::as_const(array0).data()), T const*);
    CHECK_NOEXCEPT(Array0::size());
    CHECK_NOEXCEPT(array0.data());
    CHECK_NOEXCEPT(etl::as_const(array0).data());
    CHECK(Array0::size() == 0);
    CHECK(sizeof(Array0) == 1);
    CHECK(etl::as_const(array0).data() == nullptr);
    CHECK(array0.data() == nullptr);
    CHECK(array0.data() == Array0().data());

    // Size != 0
    using Array8 = etl::uninitialized_array<T, 8>;
    auto array8  = Array8{};
    CHECK(etl::is_trivial_v<Array8>);
    CHECK_SAME_TYPE(typename Array8::value_type, T);
    CHECK_SAME_TYPE(decltype(Array8::size()), etl::size_t);
    CHECK_SAME_TYPE(decltype(array8.data()), T*);
    CHECK_SAME_TYPE(decltype(etl::as_const(array8).data()), T const*);
    CHECK_NOEXCEPT(Array8::size());
    CHECK_NOEXCEPT(array8.data());
    CHECK_NOEXCEPT(etl::as_const(array8).data());
    CHECK(Array8::size() == 8);
    CHECK(sizeof(Array8) == sizeof(T) * Array8::size());
    CHECK(etl::as_const(array8).data() != nullptr);
    CHECK(array8.data() != nullptr);
    CHECK(array8.data() != Array8().data());

    return true;
}

constexpr auto test_cx() -> bool
{
    CHECK(test_trivial<etl::int8_t>());
    CHECK(test_trivial<etl::int16_t>());
    CHECK(test_trivial<etl::int32_t>());
    CHECK(test_trivial<etl::int64_t>());
    CHECK(test_trivial<etl::uint8_t>());
    CHECK(test_trivial<etl::uint16_t>());
    CHECK(test_trivial<etl::uint32_t>());
    CHECK(test_trivial<etl::uint64_t>());
    CHECK(test_trivial<float>());
    CHECK(test_trivial<double>());
    return true;
}

auto test_non_trivial() -> bool
{
    using Array0 = etl::uninitialized_array<NonTrivial, 0>;
    using Array8 = etl::uninitialized_array<NonTrivial, 8>;

    CHECK(etl::is_trivial_v<Array8>);
    CHECK(etl::is_trivial_v<Array0>);
    CHECK_FALSE(etl::is_trivial_v<NonTrivial>);

    // Size == 0
    auto array0 = Array0{};
    CHECK(etl::is_empty_v<Array0>);
    CHECK(etl::is_trivial_v<Array0>);
    CHECK_SAME_TYPE(typename Array0::value_type, NonTrivial);
    CHECK_SAME_TYPE(decltype(Array0::size()), etl::size_t);
    CHECK_SAME_TYPE(decltype(array0.data()), NonTrivial*);
    CHECK_SAME_TYPE(decltype(etl::as_const(array0).data()), NonTrivial const*);
    CHECK_NOEXCEPT(Array0::size());
    CHECK_NOEXCEPT(array0.data());
    CHECK_NOEXCEPT(etl::as_const(array0).data());
    CHECK(Array0::size() == 0);
    CHECK(sizeof(Array0) == 1);
    CHECK(etl::as_const(array0).data() == nullptr);
    CHECK(array0.data() == nullptr);
    CHECK(array0.data() == Array0().data());

    // Size != 0
    auto array8 = Array8{};
    CHECK(etl::is_trivial_v<Array8>);
    CHECK_SAME_TYPE(typename Array8::value_type, NonTrivial);
    CHECK_SAME_TYPE(decltype(Array8::size()), etl::size_t);
    CHECK_SAME_TYPE(decltype(array8.data()), NonTrivial*);
    CHECK_SAME_TYPE(decltype(etl::as_const(array8).data()), NonTrivial const*);
    CHECK_NOEXCEPT(Array8::size());
    CHECK_NOEXCEPT(array8.data());
    CHECK_NOEXCEPT(etl::as_const(array8).data());
    CHECK(Array8::size() == 8);
    CHECK(sizeof(Array8) == sizeof(NonTrivial) * Array8::size());
    CHECK(etl::as_const(array8).data() != nullptr);
    CHECK(array8.data() != nullptr);
    CHECK(array8.data() != Array8().data());

    return true;
}

} // namespace

auto main() -> int
{
    STATIC_CHECK(test_cx());
    CHECK(test_non_trivial());
    return 0;
}
