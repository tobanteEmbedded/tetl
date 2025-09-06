// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2021 Tobias Hienzsch
#include "testing/testing.hpp"

#include <etl/new.hpp>

#if defined(TETL_ENABLE_CXX_MODULES)
import etl;
#else
    #include <etl/array.hpp>
    #include <etl/cmath.hpp>
    #include <etl/cstddef.hpp>
    #include <etl/memory.hpp>
#endif

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)

namespace {
struct Counter {
    int& value; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)

    Counter(int& v)
        : value(v)
    {
    }

    ~Counter()
    {
        value++;
    }
};

} // namespace

template <typename T>
static auto test() -> bool
{
    // "scalar"
    {
        auto deleter = etl::default_delete<T>();
        auto* ptr    = ::new T{};
        deleter(ptr);
    }

    // "array"
    {
        auto deleter = etl::default_delete<T[]>();
        auto* ptr    = ::new T[512];
        deleter(ptr);
    }

    {
        auto val = T(14.3);
        CHECK(etl::addressof(val) == &val);
        CHECK(etl::addressof(etl::log2f) == &etl::log2f);
    }
    {
        alignas(Counter) etl::byte buffer[sizeof(Counter) * 8];

        auto counter = 0;
        for (auto i = 0U; i < 8; ++i) {
            new (buffer + (sizeof(Counter) * i)) Counter{counter};
        }
        CHECK(counter == 0);

        auto* ptr = reinterpret_cast<Counter*>(&buffer[0]);
        for (auto i = 0U; i < 8; ++i) {
            etl::destroy_at(ptr + i);
        }

        CHECK(counter == 8);
    }

    {
        alignas(Counter) etl::byte buffer[sizeof(Counter) * 8];

        auto counter = 0;
        for (auto i = 0U; i < 8; ++i) {
            new (buffer + (sizeof(Counter) * i)) Counter{counter};
        }
        CHECK(counter == 0);

        auto* ptr = reinterpret_cast<Counter*>(&buffer[0]);
        etl::destroy(ptr, ptr + 8);

        CHECK(counter == 8);
    }

    {
        alignas(Counter) etl::byte buffer[sizeof(Counter) * 8];

        auto counter = 0;
        for (auto i = 0U; i < 8; ++i) {
            new (&buffer[0] + (sizeof(Counter) * i)) Counter{counter};
        }
        CHECK(counter == 0);

        auto* ptr = reinterpret_cast<Counter*>(&buffer[0]);
        etl::destroy_n(ptr, 4);

        CHECK(counter == 4);
    }

    {
        auto foo = T(1);
        CHECK(etl::assume_aligned<alignof(T), T>(&foo) == &foo);
    }

    return true;
}

static auto test_all() -> bool
{
    CHECK(test<signed char>());
    CHECK(test<signed short>());
    CHECK(test<signed int>());
    CHECK(test<signed long>());
    CHECK(test<signed long long>());

    CHECK(test<unsigned char>());
    CHECK(test<unsigned short>());
    CHECK(test<unsigned int>());
    CHECK(test<unsigned long>());
    CHECK(test<unsigned long long>());

    CHECK(test<char>());
    CHECK(test<char8_t>());
    CHECK(test<char16_t>());
    CHECK(test<char32_t>());
    CHECK(test<wchar_t>());

    CHECK(test<float>());
    CHECK(test<double>());
    CHECK(test<long double>());
    return true;
}

auto main() -> int
{
    CHECK(test_all());
    return 0;
}

#else
auto main() -> int
{
    return 0;
}
#endif
