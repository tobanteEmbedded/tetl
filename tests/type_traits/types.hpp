/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_TEST_TYPE_TRAITS_TYPES_HPP
#define TETL_TEST_TYPE_TRAITS_TYPES_HPP

enum Enum { efoo, ebar, ebaz };
enum EnumWithType : long { ewt1, ewt2 };

enum struct ScopedEnum { foo, bar, baz };
enum struct ScopedEnumWithType : long { v1, v2 };

struct EmptyClass {
};

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
    virtual auto foo() -> void = 0;
};

struct VirtualDtor {
    virtual ~VirtualDtor() noexcept { } // NOLINT
};

struct DerivedFromVirtualDtor : VirtualDtor {
};

struct Movable {
    Movable();
    Movable(Movable&&);                    // NOLINT
    auto operator=(Movable&&) -> Movable&; // NOLINT
};

struct MovableOnly {
    MovableOnly();

    MovableOnly(MovableOnly const&) = delete;
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

using PointerToMemberObj         = int VirtualDtor::*;
using PointerToConstMemberObj    = int const VirtualDtor::*;
using PointerToVolatileMemberObj = int volatile VirtualDtor::*;
using PointerToCVMemberObj       = int const volatile VirtualDtor::*;

using PointerToMemberFunc         = void (VirtualDtor::*)();
using PointerToConstMemberFunc    = void (VirtualDtor::*)() const;
using PointerToVolatileMemberFunc = void (VirtualDtor::*)() volatile;
using PointerToCVMemberFunc       = void (VirtualDtor::*)() const volatile;

#endif // TETL_TEST_TYPE_TRAITS_TYPES_HPP