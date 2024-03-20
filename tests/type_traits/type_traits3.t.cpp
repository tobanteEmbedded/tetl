// SPDX-License-Identifier: BSL-1.0

#include <etl/type_traits.hpp>

#include <etl/cstdint.hpp>

#include "testing/testing.hpp"
#include "testing/types.hpp"

namespace {
[[nodiscard]] auto func2(char /*ignore*/) -> int (*)() { return nullptr; }

template <typename T>
class Foo {
    T v1;      // NOLINT
    double v2; // NOLINT

public:
    Foo(T n) : v1(n), v2() { }

    Foo(T n, double f) noexcept : v1(n), v2(f) { }
};

} // namespace

template <typename T>
constexpr auto test() -> bool
{
    CHECK_IS_TRAIT_CV(is_copy_constructible, T);
    CHECK_IS_TRAIT_CV(is_copy_constructible, T&);
    CHECK_IS_TRAIT_C(is_copy_constructible, CopyAndMovable);
    CHECK_IS_TRAIT_C_FALSE(is_copy_constructible, MovableOnly);

    CHECK_IS_TRAIT_CV(is_trivially_copy_constructible, T);
    CHECK_IS_TRAIT_CV(is_trivially_copy_constructible, T*);
    CHECK_IS_TRAIT_CV(is_trivially_copy_constructible, EmptyClass);
    CHECK_IS_TRAIT_CV_FALSE(is_trivially_copy_constructible, T&);

    CHECK_IS_TRAIT_CV(is_scoped_enum, ScopedEnum);
    CHECK_IS_TRAIT_CV(is_scoped_enum, ScopedEnumWithType);

    CHECK_IS_TRAIT_CV_FALSE(is_scoped_enum, T);
    CHECK_IS_TRAIT_CV_FALSE(is_scoped_enum, EmptyClass);
    CHECK_IS_TRAIT_CV_FALSE(is_scoped_enum, EmptyUnion);
    CHECK_IS_TRAIT_CV_FALSE(is_scoped_enum, Enum);
    CHECK_IS_TRAIT_CV_FALSE(is_scoped_enum, EnumWithType);

    CHECK_IS_TRAIT_CV(is_constructible, T);
    CHECK_IS_TRAIT_CV(is_constructible, T*);
    CHECK_IS_TRAIT_FALSE(is_constructible, T&);
    CHECK_IS_TRAIT_FALSE(is_constructible, T const&);

    CHECK(etl::is_constructible_v<Foo<T>, T>);
    CHECK(etl::is_constructible_v<Foo<T>, T, double>);
    CHECK_FALSE((etl::is_constructible_v<Foo<T>, T, struct S>));

    {
        CHECK(etl::conjunction_v<etl::true_type>);
        CHECK(etl::conjunction_v<etl::true_type, etl::true_type>);
        CHECK_FALSE((etl::conjunction_v<etl::false_type>));

        CHECK(etl::conjunction_v<etl::is_same<T, T>, etl::is_same<T const, T const>>);
        CHECK_FALSE((etl::conjunction_v<etl::is_same<T, T>, etl::false_type>));
    }

    {
        CHECK_FALSE((etl::disjunction_v<etl::false_type>));
        CHECK_FALSE((etl::disjunction_v<etl::false_type, etl::false_type>));

        CHECK(etl::disjunction_v<etl::true_type>);
        CHECK(etl::disjunction_v<etl::true_type, etl::true_type>);
        CHECK(etl::disjunction_v<etl::true_type, etl::false_type>);

        CHECK(etl::disjunction_v<etl::is_same<T, T>, etl::is_same<T const, T const>>);
        CHECK(etl::disjunction_v<etl::is_same<T, T>, etl::false_type>);
    }

    CHECK_TRAIT_VALUE(negation, etl::true_type, false);
    CHECK_TRAIT_VALUE(negation, etl::false_type, true);

    CHECK(etl::is_swappable_with_v<T&, T&>);

    {
        CHECK(etl::is_trivially_copyable_v<T>);
        CHECK(etl::is_trivially_copyable_v<T*>);

        struct TCA { // NOLINT
            int m;
        };

        struct TCB { // NOLINT

            TCB(TCB const& /*ignore*/) { }
        };

        struct TCD { // NOLINT
            TCD(TCD const& /*ignore*/) = default;

            TCD(int x) : m(x + 1) { }

            int m;
        };

        CHECK(etl::is_trivially_copyable<TCA>::value);
        CHECK(etl::is_trivially_copyable<TCD>::value);

        CHECK_FALSE((etl::is_trivially_copyable<TCB>::value));
    }

    {
        // using T = T;

        // CHECK(etl::is_trivial_v<T>);
        // CHECK(etl::is_trivial_v<T const>);
        // CHECK(etl::is_trivial_v<T volatile>);
        // CHECK(etl::is_trivial_v<T const volatile>);

        struct non_trivial_type {
            non_trivial_type() { } // NOLINT
        };

        CHECK_FALSE((etl::is_trivial_v<non_trivial_type>));
        CHECK_FALSE((etl::is_trivial_v<non_trivial_type const>));
        CHECK_FALSE((etl::is_trivial_v<non_trivial_type volatile>));
        CHECK_FALSE((etl::is_trivial_v<non_trivial_type const volatile>));
    }

    struct S {
        auto operator()(char /*unused*/, int& /*unused*/) -> T { return T(2); }

        auto operator()(int /*unused*/) -> float { return 1.0F; }
    };

    CHECK_SAME_TYPE(etl::invoke_result_t<S, char, int&>, T);
    CHECK_SAME_TYPE(etl::invoke_result_t<S, int>, float);

    CHECK(etl::is_invocable_v<T()>);
    CHECK_FALSE((etl::is_invocable_v<T(), T>));

    CHECK(etl::is_invocable_r_v<T, T()>);
    CHECK_FALSE(etl::is_invocable_r_v<T*, T()>);
    CHECK(etl::is_invocable_r_v<void, void(T), T>);
    CHECK_FALSE(etl::is_invocable_r_v<void, void(T), void>);
    CHECK(etl::is_invocable_r_v<int (*)(), decltype(func2), char>);
    CHECK_FALSE(etl::is_invocable_r_v<T (*)(), decltype(func2), void>);
    etl::ignore_unused(func2);

    return true;
}

constexpr auto test_all() -> bool
{
    CHECK(test<etl::uint8_t>());
    CHECK(test<etl::int8_t>());
    CHECK(test<etl::uint16_t>());
    CHECK(test<etl::int16_t>());
    CHECK(test<etl::uint32_t>());
    CHECK(test<etl::int32_t>());
    CHECK(test<etl::uint64_t>());
    CHECK(test<etl::int64_t>());

    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());

    return true;
}

auto main() -> int
{
    STATIC_CHECK(test_all());
    return 0;
}
