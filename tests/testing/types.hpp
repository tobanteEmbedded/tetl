/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TEST_TYPE_TRAITS_TYPES_HPP
#define TETL_TEST_TYPE_TRAITS_TYPES_HPP

enum Enum { efoo, ebar, ebaz };
enum EnumWithType : long { ewt1, ewt2 };

enum struct ScopedEnum { foo, bar, baz };
enum struct ScopedEnumWithType : long { v1, v2 };

struct EmptyClass { };

struct DummyClass {
    int i;   // NOLINT
    float f; // NOLINT
};

union EmptyUnion {
};

union DummyUnion {
    int i;   // NOLINT
    float f; // NOLINT
};

struct Abstract {
    virtual ~Abstract()        = default;
    virtual auto foo() -> void = 0;
};

struct VirtualDtor {
    virtual ~VirtualDtor() noexcept { } // NOLINT
};

struct DerivedFromVirtualDtor : VirtualDtor { };

struct CopyAndMovable {
    CopyAndMovable();

    CopyAndMovable(CopyAndMovable const&);
    auto operator=(CopyAndMovable const&) -> CopyAndMovable&;

    CopyAndMovable(CopyAndMovable&&);                    // NOLINT
    auto operator=(CopyAndMovable&&) -> CopyAndMovable&; // NOLINT
};

struct MovableOnly {
    MovableOnly();

    MovableOnly(MovableOnly const&)                    = delete;
    auto operator=(MovableOnly const&) -> MovableOnly& = delete;

    MovableOnly(MovableOnly&&);                    // NOLINT
    auto operator=(MovableOnly&&) -> MovableOnly&; // NOLINT
};

struct Throws {
    Throws() noexcept(false);                                 // NOLINT
    Throws(Throws const&) noexcept(false);                    // NOLINT
    auto operator=(Throws const&) noexcept(false) -> Throws&; // NOLINT
    ~Throws() noexcept(false);                                // NOLINT
};

struct TriviallyConstructable {
    TriviallyConstructable() = default; // trivial and non-throwing
    int n;
};

struct NonTriviallyConstructable {
    NonTriviallyConstructable(int& n) : ref { n } { }

    int& ref;
};

struct TrivialDtor { };

struct TrivialDtorDefaulted {
    ~TrivialDtorDefaulted() = default;
};

struct NonTrivialDtor {
    ~NonTrivialDtor() { } // NOLINT
};

struct NonTrivialDtorMember {
    NonTrivialDtor member;
};

using PointerToMemberObj         = int VirtualDtor::*;
using PointerToConstMemberObj    = int VirtualDtor::*const;
using PointerToVolatileMemberObj = int VirtualDtor::*volatile;
using PointerToCVMemberObj       = int const volatile VirtualDtor::*;

using PointerToMemberFunc         = void (VirtualDtor::*)();
using PointerToConstMemberFunc    = void (VirtualDtor::*)() const;
using PointerToVolatileMemberFunc = void (VirtualDtor::*)() volatile;
using PointerToCVMemberFunc       = void (VirtualDtor::*)() const volatile;

#define TEST_IS_TRAIT(trait, type)                                                                                     \
    do {                                                                                                               \
        assert(etl::is_base_of_v<etl::true_type, etl::trait<type>>);                                                   \
        assert((etl::trait<type>::value));                                                                             \
        assert((etl::TETL_PP_CONCAT(trait, _v) < type >));                                                             \
    } while (false)

#define TEST_IS_TRAIT_FALSE(trait, type)                                                                               \
    do {                                                                                                               \
        assert((etl::is_base_of_v<etl::false_type, etl::trait<type>>));                                                \
        assert(!(etl::trait<type>::value));                                                                            \
        assert(!(etl::TETL_PP_CONCAT(trait, _v) < type >));                                                            \
    } while (false)

#define TEST_IS_TRAIT_C(trait, type)                                                                                   \
    TEST_IS_TRAIT(trait, type);                                                                                        \
    TEST_IS_TRAIT(trait, const type)

#define TEST_IS_TRAIT_C_FALSE(trait, type)                                                                             \
    TEST_IS_TRAIT_FALSE(trait, type);                                                                                  \
    TEST_IS_TRAIT_FALSE(trait, const type)

#define TEST_IS_TRAIT_V(trait, type)                                                                                   \
    TEST_IS_TRAIT(trait, type);                                                                                        \
    TEST_IS_TRAIT(trait, volatile type)

#define TEST_IS_TRAIT_V_FALSE(trait, type)                                                                             \
    TEST_IS_TRAIT_FALSE(trait, type);                                                                                  \
    TEST_IS_TRAIT_FALSE(trait, volatile type)

#define TEST_IS_TRAIT_CV(trait, type)                                                                                  \
    TEST_IS_TRAIT(trait, type);                                                                                        \
    TEST_IS_TRAIT(trait, const type);                                                                                  \
    TEST_IS_TRAIT(trait, volatile type);                                                                               \
    TEST_IS_TRAIT(trait, const volatile type)

#define TEST_IS_TRAIT_CV_FALSE(trait, type)                                                                            \
    TEST_IS_TRAIT_FALSE(trait, type);                                                                                  \
    TEST_IS_TRAIT_FALSE(trait, const type);                                                                            \
    TEST_IS_TRAIT_FALSE(trait, volatile type);                                                                         \
    TEST_IS_TRAIT_FALSE(trait, const volatile type)

#define TEST_TRAIT_VALUE(trait, type, expected)                                                                        \
    do {                                                                                                               \
        assert((etl::trait<type>::value == (expected)));                                                               \
        assert(((etl::TETL_PP_CONCAT(trait, _v) < type >) == (expected)));                                             \
    } while (false)

#define TEST_TRAIT_VALUE_CV(trait, type, expected)                                                                     \
    TEST_TRAIT_VALUE(trait, type, expected);                                                                           \
    TEST_TRAIT_VALUE(trait, const type, expected);                                                                     \
    TEST_TRAIT_VALUE(trait, volatile type, expected);                                                                  \
    TEST_TRAIT_VALUE(trait, const volatile type, expected)

#define TEST_TRAIT_TYPE(trait, T, e)                                                                                   \
    do {                                                                                                               \
        assert((etl::is_same_v<typename etl::trait<T>::type, e>));                                                     \
        assert((etl::is_same_v<etl::TETL_PP_CONCAT(trait, _t) < T>, e >));                                             \
    } while (false)

#define TEST_TRAIT_TYPE_CV(trait, type, expected)                                                                      \
    TEST_TRAIT_TYPE(trait, type, expected);                                                                            \
    TEST_TRAIT_TYPE(trait, const type, expected);                                                                      \
    TEST_TRAIT_TYPE(trait, volatile type, expected);                                                                   \
    TEST_TRAIT_TYPE(trait, const volatile type, expected)

#endif // TETL_TEST_TYPE_TRAITS_TYPES_HPP