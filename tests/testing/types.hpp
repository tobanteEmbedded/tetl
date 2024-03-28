// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_TEST_TESTING_TYPES_HPP
#define TETL_TEST_TESTING_TYPES_HPP

enum Enum {
    efoo,
    ebar,
    ebaz
};

enum EnumWithType : long {
    ewt1,
    ewt2
};

enum struct ScopedEnum {
    foo,
    bar,
    baz
};
enum struct ScopedEnumWithType : long {
    v1,
    v2
};

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
    NonTriviallyConstructable(int& n) : ref{n} { }

    int& ref; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)
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

#define CHECK_IS_TRAIT(trait, type)                                                                                    \
    do {                                                                                                               \
        CHECK(etl::is_base_of_v<etl::true_type, etl::trait<type>>);                                                    \
        CHECK(etl::trait<type>::value);                                                                                \
        CHECK(etl::TETL_CONCAT(trait, _v) < type >);                                                                   \
    } while (false)

#define CHECK_IS_TRAIT_FALSE(trait, type)                                                                              \
    do {                                                                                                               \
        CHECK(etl::is_base_of_v<etl::false_type, etl::trait<type>>);                                                   \
        CHECK_FALSE(etl::trait<type>::value);                                                                          \
        CHECK_FALSE(etl::TETL_CONCAT(trait, _v) < type >);                                                             \
    } while (false)

#define CHECK_IS_TRAIT_C(trait, type)                                                                                  \
    CHECK_IS_TRAIT(trait, type);                                                                                       \
    CHECK_IS_TRAIT(trait, const type)

#define CHECK_IS_TRAIT_C_FALSE(trait, type)                                                                            \
    CHECK_IS_TRAIT_FALSE(trait, type);                                                                                 \
    CHECK_IS_TRAIT_FALSE(trait, const type)

#define CHECK_IS_TRAIT_V(trait, type)                                                                                  \
    CHECK_IS_TRAIT(trait, type);                                                                                       \
    CHECK_IS_TRAIT(trait, volatile type)

#define CHECK_IS_TRAIT_V_FALSE(trait, type)                                                                            \
    CHECK_IS_TRAIT_FALSE(trait, type);                                                                                 \
    CHECK_IS_TRAIT_FALSE(trait, volatile type)

#define CHECK_IS_TRAIT_CV(trait, type)                                                                                 \
    CHECK_IS_TRAIT(trait, type);                                                                                       \
    CHECK_IS_TRAIT(trait, const type);                                                                                 \
    CHECK_IS_TRAIT(trait, volatile type);                                                                              \
    CHECK_IS_TRAIT(trait, const volatile type)

#define CHECK_IS_TRAIT_CV_FALSE(trait, type)                                                                           \
    CHECK_IS_TRAIT_FALSE(trait, type);                                                                                 \
    CHECK_IS_TRAIT_FALSE(trait, const type);                                                                           \
    CHECK_IS_TRAIT_FALSE(trait, volatile type);                                                                        \
    CHECK_IS_TRAIT_FALSE(trait, const volatile type)

#define CHECK_TRAIT_VALUE(trait, type, expected)                                                                       \
    do {                                                                                                               \
        CHECK(etl::trait<type>::value == (expected));                                                                  \
        CHECK((etl::TETL_CONCAT(trait, _v) < type >) == (expected));                                                   \
    } while (false)

#define CHECK_TRAIT_VALUE_CV(trait, type, expected)                                                                    \
    CHECK_TRAIT_VALUE(trait, type, expected);                                                                          \
    CHECK_TRAIT_VALUE(trait, const type, expected);                                                                    \
    CHECK_TRAIT_VALUE(trait, volatile type, expected);                                                                 \
    CHECK_TRAIT_VALUE(trait, const volatile type, expected)

#define CHECK_TRAIT_TYPE(trait, T, e)                                                                                  \
    do {                                                                                                               \
        CHECK(etl::is_same_v<typename etl::trait<T>::type, e>);                                                        \
        CHECK(etl::is_same_v<etl::TETL_CONCAT(trait, _t) < T>, e >);                                                   \
    } while (false)

#define CHECK_TRAIT_TYPE_CV(trait, type, expected)                                                                     \
    CHECK_TRAIT_TYPE(trait, type, expected);                                                                           \
    CHECK_TRAIT_TYPE(trait, const type, expected);                                                                     \
    CHECK_TRAIT_TYPE(trait, volatile type, expected);                                                                  \
    CHECK_TRAIT_TYPE(trait, const volatile type, expected)

#endif // TETL_TEST_TESTING_TYPES_HPP
