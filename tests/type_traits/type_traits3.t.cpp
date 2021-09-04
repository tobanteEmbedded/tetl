/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/type_traits.hpp"

#include "testing.hpp"
#include "types.hpp"

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
    TEST_IS_TRAIT_CV(is_copy_constructible, T);
    TEST_IS_TRAIT_CV(is_copy_constructible, T&);
    TEST_IS_TRAIT_C(is_copy_constructible, CopyAndMovable);
    TEST_IS_TRAIT_C_FALSE(is_copy_constructible, MovableOnly);

    TEST_IS_TRAIT_CV(is_trivially_copy_constructible, T);
    TEST_IS_TRAIT_CV(is_trivially_copy_constructible, T*);
    TEST_IS_TRAIT_CV(is_trivially_copy_constructible, EmptyClass);
    TEST_IS_TRAIT_CV_FALSE(is_trivially_copy_constructible, T&);

    TEST_IS_TRAIT_CV(is_scoped_enum, ScopedEnum);
    TEST_IS_TRAIT_CV(is_scoped_enum, ScopedEnumWithType);

    TEST_IS_TRAIT_CV_FALSE(is_scoped_enum, T);
    TEST_IS_TRAIT_CV_FALSE(is_scoped_enum, EmptyClass);
    TEST_IS_TRAIT_CV_FALSE(is_scoped_enum, EmptyUnion);
    TEST_IS_TRAIT_CV_FALSE(is_scoped_enum, Enum);
    TEST_IS_TRAIT_CV_FALSE(is_scoped_enum, EnumWithType);

    TEST_IS_TRAIT_CV(is_constructible, T);
    TEST_IS_TRAIT_CV(is_constructible, T*);
    TEST_IS_TRAIT_FALSE(is_constructible, T&);
    TEST_IS_TRAIT_FALSE(is_constructible, T const&);

    assert((etl::is_constructible_v<Foo<T>, T>));
    assert((etl::is_constructible_v<Foo<T>, T, double>));
    assert(!(etl::is_constructible_v<Foo<T>, T, struct S>));

    {
        using etl::conjunction_v;
        using etl::is_same;

        assert((conjunction_v<etl::true_type>));
        assert((conjunction_v<etl::true_type, etl::true_type>));
        assert(!(conjunction_v<etl::false_type>));

        assert((conjunction_v<is_same<T, T>, is_same<T const, T const>>));
        assert(!(conjunction_v<is_same<T, T>, etl::false_type>));
    }

    {
        using etl::disjunction_v;
        using etl::is_same;

        assert(!(disjunction_v<etl::false_type>));
        assert(!(disjunction_v<etl::false_type, etl::false_type>));

        assert((disjunction_v<etl::true_type>));
        assert((disjunction_v<etl::true_type, etl::true_type>));
        assert((disjunction_v<etl::true_type, etl::false_type>));

        assert((disjunction_v<is_same<T, T>, is_same<T const, T const>>));
        assert((disjunction_v<is_same<T, T>, etl::false_type>));
    }

    TEST_TRAIT_VALUE(negation, etl::true_type, false);
    TEST_TRAIT_VALUE(negation, etl::false_type, true);

    assert((etl::is_swappable_with_v<T&, T&>));

    {
        using etl::is_trivially_copyable_v;

        assert((is_trivially_copyable_v<T>));
        assert((is_trivially_copyable_v<T*>));

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

        assert((etl::is_trivially_copyable<TCA>::value));
        assert((etl::is_trivially_copyable<TCD>::value));

        assert(!(etl::is_trivially_copyable<TCB>::value));
    }

    {
        // using T = T;

        // assert((etl::is_trivial_v<T>));
        // assert((etl::is_trivial_v<T const>));
        // assert((etl::is_trivial_v<T volatile>));
        // assert((etl::is_trivial_v<T const volatile>));

        struct non_trivial_type {
            non_trivial_type() { } // NOLINT
        };

        assert(!(etl::is_trivial_v<non_trivial_type>));
        assert(!(etl::is_trivial_v<non_trivial_type const>));
        assert(!(etl::is_trivial_v<non_trivial_type volatile>));
        assert(!(etl::is_trivial_v<non_trivial_type const volatile>));
    }

    struct S {
        auto operator()(char /*unused*/, int& /*unused*/) -> T { return T(2); }
        auto operator()(int /*unused*/) -> float { return 1.0F; }
    };

    assert((etl::is_same_v<etl::invoke_result_t<S, char, int&>, T>));
    assert((etl::is_same_v<etl::invoke_result_t<S, int>, float>));

    assert(etl::is_invocable_v<T()>);
    assert(!(etl::is_invocable_v<T(), T>));

    assert((etl::is_invocable_r_v<T, T()>));
    assert((!etl::is_invocable_r_v<T*, T()>));
    assert((etl::is_invocable_r_v<void, void(T), T>));
    assert((!etl::is_invocable_r_v<void, void(T), void>));
    assert((etl::is_invocable_r_v<int (*)(), decltype(func2), char>));
    assert((!etl::is_invocable_r_v<T (*)(), decltype(func2), void>));
    etl::ignore_unused(func2);

    return true;
}

constexpr auto test_all() -> bool
{
    assert(test<etl::uint8_t>());
    assert(test<etl::int8_t>());
    assert(test<etl::uint16_t>());
    assert(test<etl::int16_t>());
    assert(test<etl::uint32_t>());
    assert(test<etl::int32_t>());
    assert(test<etl::uint64_t>());
    assert(test<etl::int64_t>());

    assert(test<float>());
    assert(test<double>());
    assert(test<long double>());

    return true;
}

auto main() -> int
{
    assert(test_all());
    static_assert(test_all());
    return 0;
}