// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch

#include "testing/testing.hpp"

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/cstddef.hpp>
    #include <etl/cstdint.hpp>
    #include <etl/memory.hpp>
#endif

template <typename T>
static auto test() -> bool
{
    {
        using int_ptr_t = etl::small_ptr<int, 0, T>;
        CHECK(sizeof(int_ptr_t) == sizeof(T));

        using float_ptr_t = etl::small_ptr<float, 0, T>;
        CHECK(sizeof(float_ptr_t) == sizeof(T));
    }

    {
        using ptr_t = etl::small_ptr<T, 0, etl::uintptr_t>;
        auto ptr    = ptr_t{};
        etl::ignore_unused(ptr);
        CHECK(true);
    }

    {
        using ptr_t = etl::small_ptr<T, 0, etl::uintptr_t>;
        CHECK(ptr_t{nullptr}.compressed_value() == 0U);
    }

    {
        using ptr_t = etl::small_ptr<T const, 16, etl::uintptr_t>;

        auto ptr = ptr_t{reinterpret_cast<T*>(32)};
        CHECK(ptr.compressed_value() == static_cast<etl::uintptr_t>(32 - 16));
        CHECK(reinterpret_cast<etl::uintptr_t>(ptr.operator->()) == static_cast<etl::uintptr_t>(32));

        ptr = ptr_t{reinterpret_cast<T*>(2048)};
        CHECK(ptr.compressed_value() == static_cast<etl::uintptr_t>(2048 - 16));
        CHECK(reinterpret_cast<etl::uintptr_t>(ptr.operator->()) == static_cast<etl::uintptr_t>(2048));

        ptr = ptr_t{reinterpret_cast<T*>(4100)};
        CHECK(ptr.compressed_value() == static_cast<etl::uintptr_t>(4100 - 16));
        CHECK(reinterpret_cast<etl::uintptr_t>(ptr.operator->()) == static_cast<etl::uintptr_t>(4100));
    }

    // get mutable
    {
        using ptr_t = etl::small_ptr<T const, 0, etl::uintptr_t>;
        auto val    = T(1.43);
        auto ptr    = ptr_t{&val};
        CHECK(ptr.get() == &val);
    }

    // get const
    {
        using ptr_t    = etl::small_ptr<T const, 0, etl::uintptr_t>;
        auto const val = T(1.43);
        auto const ptr = ptr_t{&val};
        CHECK(ptr.get() == &val);
    }

    // mutable
    {
        using ptr_t = etl::small_ptr<T, 0, etl::uintptr_t>;
        auto val    = T(1.43);
        auto ptr    = ptr_t{&val};
        CHECK(*ptr == val);
    }

    // const
    {
        using ptr_t    = etl::small_ptr<T const, 0, etl::uintptr_t>;
        auto const val = T(1.43);
        auto const ptr = ptr_t{&val};
        CHECK(*ptr == val);
    }

    {
        using ptr_t = etl::small_ptr<T, 0, etl::uintptr_t>;

        auto val  = T(1.43);
        auto ptr  = ptr_t{&val};
        auto func = [t = val](T* p) { CHECK(*p == t); };
        func(ptr);
    }

    {
        using ptr_t = etl::small_ptr<T const, 0, etl::uintptr_t>;

        auto const val = T(1.43);
        auto const ptr = ptr_t{&val};
        auto func      = [t = val](T const* p) { CHECK(*p == t); };
        func(ptr);
    }

    {
        using ptr_t = etl::small_ptr<T const, 0, etl::uintptr_t>;
        auto data   = etl::array<T, 4>{};
        CHECK(ptr_t{&data[1]} - ptr_t{&data[0]} == 1);
        CHECK(ptr_t{&data[2]} - ptr_t{&data[0]} == 2);
        CHECK(ptr_t{&data[3]} - ptr_t{&data[0]} == 3);
    }

    // pre
    {
        using ptr_t     = etl::small_ptr<T const, 0, etl::uintptr_t>;
        auto const data = etl::array<T, 4>{};
        auto ptr        = ptr_t{&data[1]};
        // NOLINTNEXTLINE(bugprone-assert-side-effect)
        CHECK((--ptr).get() == ptr_t{&data[0]}.get());
    }

    // post
    {
        using ptr_t = etl::small_ptr<T const, 0, etl::uintptr_t>;

        auto const data = etl::array<T, 4>{};
        auto ptr        = ptr_t{&data[1]};
        // NOLINTNEXTLINE(bugprone-assert-side-effect)
        CHECK((ptr--).get() == ptr_t{&data[1]}.get());
        CHECK(ptr.get() == ptr_t{&data[0]}.get());
    }

    // pre
    {
        using ptr_t     = etl::small_ptr<T const, 0, etl::uintptr_t>;
        auto const data = etl::array<T, 4>{};
        auto ptr        = ptr_t{&data[1]};
        // NOLINTNEXTLINE(bugprone-assert-side-effect)
        CHECK((++ptr).get() == ptr_t{&data[2]}.get());
    }

    // post
    {
        using ptr_t     = etl::small_ptr<T const, 0, etl::uintptr_t>;
        auto const data = etl::array<T, 4>{};
        auto ptr        = ptr_t{&data[1]};
        // NOLINTNEXTLINE(bugprone-assert-side-effect)
        CHECK((ptr++).get() == ptr_t{&data[1]}.get());
        CHECK(ptr.get() == ptr_t{&data[2]}.get());
    }

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
