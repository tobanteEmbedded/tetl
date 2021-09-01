/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#include "etl/type_traits.hpp"

// #include "etl/version.hpp"

#include "testing.hpp"

namespace {

struct A {
};

struct B {
    int m;
};

struct C {
    [[maybe_unused]] static int m;
};

struct D {
    virtual ~D() = default;
};

union E {
};

struct IsPolymorphic_A {
    int m;
};

struct IsPolymorphic_B {
    virtual void foo();
};

struct IsPolymorphic_C : IsPolymorphic_B {
};

struct IsPolymorphic_D {
    virtual ~IsPolymorphic_D() = default;
};

struct IsFinal_A {
    int m;
};

struct IsFinal_B {
    virtual void foo(); // NOLINT
};

struct IsFinal_C final : IsFinal_B {
};

struct IsFinal_D {
    virtual ~IsFinal_D() = default;
};

union IsFinal_E final {
    char data1;
    float data2;
};

struct IsAbstract_A {
    int m;
};

struct IsAbstract_B {
    virtual void foo() { }
};

struct IsAbstract_C {
    virtual void foo() = 0;
};

struct IsAbstract_D : IsAbstract_C {
};

} // namespace

constexpr auto test_all() -> bool
{
    assert((etl::is_standard_layout<A>::value));
    assert((etl::is_standard_layout_v<A>));
    assert((etl::is_standard_layout<B>::value));
    assert((etl::is_standard_layout_v<B>));
    assert((etl::is_standard_layout<C>::value));
    assert((etl::is_standard_layout_v<C>));
    assert((etl::is_standard_layout<E>::value));
    assert((etl::is_standard_layout_v<E>));
    assert((!etl::is_standard_layout<D>::value));
    assert((!etl::is_standard_layout_v<D>));

    assert((etl::is_empty<A>::value));
    assert((etl::is_empty_v<A>));
    assert((etl::is_empty<C>::value));
    assert((etl::is_empty_v<C>));

    assert((!etl::is_empty<B>::value));
    assert((!etl::is_empty_v<B>));
    assert((!etl::is_empty<D>::value));
    assert((!etl::is_empty_v<D>));
    assert((!etl::is_empty<E>::value));
    assert((!etl::is_empty_v<E>));

    assert((!etl::is_polymorphic<int>::value));
    assert((!etl::is_polymorphic_v<int>));
    assert((!etl::is_polymorphic<IsPolymorphic_A>::value));
    assert((!etl::is_polymorphic_v<IsPolymorphic_A>));

    assert((etl::is_polymorphic<IsPolymorphic_B>::value));
    assert((etl::is_polymorphic_v<IsPolymorphic_B>));
    assert((etl::is_polymorphic<IsPolymorphic_C>::value));
    assert((etl::is_polymorphic_v<IsPolymorphic_C>));
    assert((etl::is_polymorphic<IsPolymorphic_D>::value));
    assert((etl::is_polymorphic_v<IsPolymorphic_D>));

    assert((!etl::is_final<int>::value));
    assert((!etl::is_final_v<int>));
    assert((!etl::is_final<float>::value));
    assert((!etl::is_final_v<float>));
    assert((!etl::is_final<IsFinal_A>::value));
    assert((!etl::is_final_v<IsFinal_A>));
    assert((!etl::is_final<IsFinal_B>::value));
    assert((!etl::is_final_v<IsFinal_B>));
    assert((!etl::is_final<IsFinal_D>::value));
    assert((!etl::is_final_v<IsFinal_D>));

    assert((etl::is_final<IsFinal_C>::value));
    assert((etl::is_final_v<IsFinal_C>));
    assert((etl::is_final<IsFinal_E>::value));
    assert((etl::is_final_v<IsFinal_E>));

    assert((!etl::is_abstract<int>::value));
    assert((!etl::is_abstract_v<int>));
    assert((!etl::is_abstract<float>::value));
    assert((!etl::is_abstract_v<float>));
    assert((!etl::is_abstract<IsAbstract_A>::value));
    assert((!etl::is_abstract_v<IsAbstract_A>));
    assert((!etl::is_abstract<IsAbstract_B>::value));
    assert((!etl::is_abstract_v<IsAbstract_B>));

    assert((etl::is_abstract<IsAbstract_C>::value));
    assert((etl::is_abstract_v<IsAbstract_C>));
    assert((etl::is_abstract<IsAbstract_D>::value));
    assert((etl::is_abstract_v<IsAbstract_D>));

    assert((etl::is_integral_v<float> == false));
    assert((etl::is_integral_v<double> == false));
    assert((etl::is_integral_v<long double> == false));
    assert((etl::is_integral_v<struct NotIntegral> == false));
    assert((etl::is_integral_v<decltype(nullptr)> == false));

    assert((etl::is_integral_v<etl::int8_t>));
    assert((etl::is_integral_v<etl::int16_t>));
    assert((etl::is_integral_v<etl::int32_t>));
    assert((etl::is_integral_v<etl::int64_t>));
    assert((etl::is_integral_v<etl::uint8_t>));
    assert((etl::is_integral_v<etl::uint16_t>));
    assert((etl::is_integral_v<etl::uint32_t>));
    assert((etl::is_integral_v<etl::uint64_t>));

    assert((etl::is_floating_point_v<float>));
    assert((etl::is_floating_point_v<double>));
    assert((etl::is_floating_point_v<long double>));

    assert((etl::is_floating_point_v<char> == false));
    assert((etl::is_floating_point_v<int> == false));
    assert((etl::is_floating_point_v<decltype(nullptr)> == false));
    assert((etl::is_floating_point_v<struct FooBar> == false));

    assert((etl::is_null_pointer_v<int> == false));
    assert((etl::is_null_pointer_v<float> == false));
    assert((etl::is_null_pointer_v<decltype(nullptr)>));

    assert((etl::is_array_v<float> == false));
    assert((etl::is_array_v<float[]>));
    assert((etl::is_array_v<float[4]>));

    assert((etl::is_pointer_v<float*>));
    assert((etl::is_pointer_v<float> == false));

    using etl::has_virtual_destructor_v;

    assert(!(has_virtual_destructor_v<int>));
    assert(!(has_virtual_destructor_v<int const>));
    assert(!(has_virtual_destructor_v<int volatile>));
    assert(!(has_virtual_destructor_v<int const volatile>));

    assert(!(has_virtual_destructor_v<int&>));
    assert(!(has_virtual_destructor_v<int const&>));
    assert(!(has_virtual_destructor_v<int volatile&>));
    assert(!(has_virtual_destructor_v<int const volatile&>));

    assert(!(has_virtual_destructor_v<int*>));
    assert(!(has_virtual_destructor_v<int const*>));
    assert(!(has_virtual_destructor_v<int volatile*>));
    assert(!(has_virtual_destructor_v<int const volatile*>));

    struct NVS {
        ~NVS() { } // NOLINT
        float value {};
    };

    struct VS {
        virtual ~VS() { } // NOLINT
        float value {};
    };

    class NVC {
    public:
        ~NVC() { } // NOLINT
        float value {};
    };

    class VC {
    public:
        virtual ~VC() { } // NOLINT
        float value {};
    };

    assert(!(has_virtual_destructor_v<NVS>));
    assert(!(has_virtual_destructor_v<NVS const>));
    assert(!(has_virtual_destructor_v<NVS volatile>));
    assert(!(has_virtual_destructor_v<NVS const volatile>));

    assert(!(has_virtual_destructor_v<NVC>));
    assert(!(has_virtual_destructor_v<NVC const>));
    assert(!(has_virtual_destructor_v<NVC volatile>));
    assert(!(has_virtual_destructor_v<NVC const volatile>));

    assert((has_virtual_destructor_v<VS>));
    assert((has_virtual_destructor_v<VS const>));
    assert((has_virtual_destructor_v<VS volatile>));
    assert((has_virtual_destructor_v<VS const volatile>));

    assert((has_virtual_destructor_v<VC>));
    assert((has_virtual_destructor_v<VC const>));
    assert((has_virtual_destructor_v<VC volatile>));
    assert((has_virtual_destructor_v<VC const volatile>));

    return true;
}

auto main() -> int
{
    assert(test_all());
    assert((test_all()));
    return 0;
}