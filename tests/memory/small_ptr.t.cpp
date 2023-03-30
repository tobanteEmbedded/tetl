// SPDX-License-Identifier: BSL-1.0

#include "etl/memory.hpp"

#include "etl/array.hpp"
#include "etl/cstdint.hpp"

#include "testing/testing.hpp"

template <typename T>
auto test() -> bool
{

    {
        using int_ptr_t = etl::small_ptr<int, 0, T>;
        assert(sizeof(int_ptr_t) == sizeof(T));

        using float_ptr_t = etl::small_ptr<float, 0, T>;
        assert(sizeof(float_ptr_t) == sizeof(T));
    }

    {
        using ptr_t = etl::small_ptr<T, 0, etl::uintptr_t>;
        auto ptr    = ptr_t {};
        etl::ignore_unused(ptr);
        assert(true);
    }

    {
        using ptr_t = etl::small_ptr<T, 0, etl::uintptr_t>;
        assert(ptr_t { nullptr }.compressed_value() == 0U);
    }

    {
        using ptr_t = etl::small_ptr<T const, 16, etl::uintptr_t>;

        // clang-format off
        auto ptr = ptr_t { reinterpret_cast<T*>(32) };
        assert(ptr.compressed_value() == static_cast<etl::uintptr_t>(32 - 16));
        assert(reinterpret_cast<etl::uintptr_t>(ptr.operator->()) == static_cast<etl::uintptr_t>(32));

        ptr = ptr_t { reinterpret_cast<T*>(2048) };
        assert(ptr.compressed_value() == static_cast<etl::uintptr_t>(2048 - 16));
        assert(reinterpret_cast<etl::uintptr_t>(ptr.operator->()) == static_cast<etl::uintptr_t>(2048));

        ptr = ptr_t { reinterpret_cast<T*>(4100) };
        assert(ptr.compressed_value() == static_cast<etl::uintptr_t>(4100 - 16));
        assert(reinterpret_cast<etl::uintptr_t>(ptr.operator->()) == static_cast<etl::uintptr_t>(4100));
        // clang-format on
    }

    // get mutable
    {
        using ptr_t = etl::small_ptr<T const, 0, etl::uintptr_t>;
        auto val    = T(1.43);
        auto ptr    = ptr_t { &val };
        assert(ptr.get() == &val);
    }

    // get const
    {
        using ptr_t    = etl::small_ptr<T const, 0, etl::uintptr_t>;
        auto const val = T(1.43);
        auto const ptr = ptr_t { &val };
        assert(ptr.get() == &val);
    }

    // mutable
    {
        using ptr_t = etl::small_ptr<T, 0, etl::uintptr_t>;
        auto val    = T(1.43);
        auto ptr    = ptr_t { &val };
        assert(*ptr == val);
    }

    // const
    {
        using ptr_t    = etl::small_ptr<T const, 0, etl::uintptr_t>;
        auto const val = T(1.43);
        auto const ptr = ptr_t { &val };
        assert(*ptr == val);
    }

    {
        using ptr_t = etl::small_ptr<T, 0, etl::uintptr_t>;

        auto val  = T(1.43);
        auto ptr  = ptr_t { &val };
        auto func = [t = val](T* p) { assert(*p == t); };
        func(ptr);
    }

    {
        using ptr_t = etl::small_ptr<T const, 0, etl::uintptr_t>;

        auto const val = T(1.43);
        auto const ptr = ptr_t { &val };
        auto func      = [t = val](T const* p) { assert(*p == t); };
        func(ptr);
    }

    {
        using ptr_t = etl::small_ptr<T const, 0, etl::uintptr_t>;
        auto data   = etl::array<T, 4> {};
        assert(ptr_t { &data[1] } - ptr_t { &data[0] } == 1);
        assert(ptr_t { &data[2] } - ptr_t { &data[0] } == 2);
        assert(ptr_t { &data[3] } - ptr_t { &data[0] } == 3);
    }

    // pre
    {
        using ptr_t     = etl::small_ptr<T const, 0, etl::uintptr_t>;
        auto const data = etl::array<T, 4> {};
        auto ptr        = ptr_t { &data[1] };
        // NOLINTNEXTLINE(bugprone-assert-side-effect)
        assert((--ptr).get() == ptr_t { &data[0] }.get());
    }

    // post
    {
        using ptr_t = etl::small_ptr<T const, 0, etl::uintptr_t>;

        auto const data = etl::array<T, 4> {};
        auto ptr        = ptr_t { &data[1] };
        // NOLINTNEXTLINE(bugprone-assert-side-effect)
        assert((ptr--).get() == ptr_t { &data[1] }.get());
        assert(ptr.get() == ptr_t { &data[0] }.get());
    }

    // pre
    {
        using ptr_t     = etl::small_ptr<T const, 0, etl::uintptr_t>;
        auto const data = etl::array<T, 4> {};
        auto ptr        = ptr_t { &data[1] };
        // NOLINTNEXTLINE(bugprone-assert-side-effect)
        assert((++ptr).get() == ptr_t { &data[2] }.get());
    }

    // post
    {
        using ptr_t     = etl::small_ptr<T const, 0, etl::uintptr_t>;
        auto const data = etl::array<T, 4> {};
        auto ptr        = ptr_t { &data[1] };
        // NOLINTNEXTLINE(bugprone-assert-side-effect)
        assert((ptr++).get() == ptr_t { &data[1] }.get());
        assert(ptr.get() == ptr_t { &data[2] }.get());
    }

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
