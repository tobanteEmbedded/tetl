/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/type_traits.hpp"

#include "etl/version.hpp"

#include "testing.hpp"

namespace {
[[nodiscard]] auto func2(char /*ignore*/) -> int (*)() { return nullptr; }

} // namespace

template <typename T>
constexpr auto test() -> bool
{

    {
        assert((etl::is_constructible_v<T>));
        assert((etl::is_constructible_v<T*>));
        assert((etl::is_constructible_v<T, T&>));
        assert((etl::is_constructible_v<T, T const&>));

        assert(!(etl::is_constructible_v<T&>));
        assert(!(etl::is_constructible_v<T const&>));

        class Foo {
            T v1;      // NOLINT
            double v2; // NOLINT

        public:
            Foo(T n) : v1(n), v2() { }
            Foo(T n, double f) noexcept : v1(n), v2(f) { }
        };

        assert((etl::is_constructible_v<Foo, T>));
        assert((etl::is_constructible_v<Foo, T, double>));
        assert(!(etl::is_constructible_v<Foo, T, struct S>));
    }
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
    {
        class SomeClass {
        };

        enum CEnum : int {};

        enum struct Es { oz };

        enum class Ec : int {};

        assert(!(etl::is_scoped_enum_v<int>));
        assert(!(etl::is_scoped_enum<SomeClass>::value));
        assert(!(etl::is_scoped_enum<CEnum>::value));

        assert((etl::is_scoped_enum<Es>::value));
        assert((etl::is_scoped_enum_v<Ec>));
    }

    assert((etl::is_swappable_with_v<T&, T&>));

    {
        using etl::is_copy_constructible_v;

        assert((is_copy_constructible_v<T>));
        assert((is_copy_constructible_v<T&>));
        assert((is_copy_constructible_v<T const&>));
        assert((is_copy_constructible_v<T volatile&>));
        assert((is_copy_constructible_v<T const volatile&>));

        struct CopyableS {
            T value {};
        };

        class CopyableC {
        public:
            T value {};
        };

        struct NonCopyableS {
            NonCopyableS(NonCopyableS const&) = delete; // NOLINT
            T value {};
        };

        class NonCopyableC {
        public:
            NonCopyableC(NonCopyableC const&) = delete; // NOLINT
            T value {};
        };

        assert((is_copy_constructible_v<CopyableS>));
        assert((is_copy_constructible_v<CopyableS const>));
        assert(!(is_copy_constructible_v<CopyableS volatile>));
        assert(!(is_copy_constructible_v<CopyableS const volatile>));

        assert((is_copy_constructible_v<CopyableC>));
        assert((is_copy_constructible_v<CopyableC const>));
        assert(!(is_copy_constructible_v<CopyableC volatile>));
        assert(!(is_copy_constructible_v<CopyableC const volatile>));

        assert(!(is_copy_constructible_v<NonCopyableS>));
        assert(!(is_copy_constructible_v<NonCopyableS const>));
        assert(!(is_copy_constructible_v<NonCopyableS volatile>));
        assert(!(is_copy_constructible_v<NonCopyableS const volatile>));

        assert(!(is_copy_constructible_v<NonCopyableC>));
        assert(!(is_copy_constructible_v<NonCopyableC const>));
        assert(!(is_copy_constructible_v<NonCopyableC volatile>));
        assert(!(is_copy_constructible_v<NonCopyableC const volatile>));
    }

    {
        using etl::is_trivially_copy_constructible_v;

        assert((is_trivially_copy_constructible_v<T>));

        assert((is_trivially_copy_constructible_v<T*>));
        assert((is_trivially_copy_constructible_v<T const*>));
        assert((is_trivially_copy_constructible_v<T volatile*>));
        assert((is_trivially_copy_constructible_v<T const volatile*>));

        assert(!(is_trivially_copy_constructible_v<T&>));
        assert(!(is_trivially_copy_constructible_v<T const&>));
        assert(!(is_trivially_copy_constructible_v<T volatile&>));
        assert(!(is_trivially_copy_constructible_v<T const volatile&>));

        struct TCS {
        };

        class TCC {
        public:
            T value;
        };

        assert((is_trivially_copy_constructible_v<TCS>));
        assert((is_trivially_copy_constructible_v<TCS const>));
        assert((is_trivially_copy_constructible_v<TCS volatile>));
        assert((is_trivially_copy_constructible_v<TCS const volatile>));

        assert((is_trivially_copy_constructible_v<TCC>));
        assert((is_trivially_copy_constructible_v<TCC const>));
        assert((is_trivially_copy_constructible_v<TCC volatile>));
        assert((is_trivially_copy_constructible_v<TCC const volatile>));
    }

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