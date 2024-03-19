// SPDX-License-Identifier: BSL-1.0

#include <etl/memory.hpp>

#include <etl/array.hpp>
#include <etl/cstddef.hpp>
#include <etl/cstdint.hpp>
#include <etl/new.hpp>

#include "testing/testing.hpp"

#if not defined(TETL_WORKAROUND_AVR_BROKEN_TESTS)

namespace {
struct Counter {
    int& value; // NOLINT(cppcoreguidelines-avoid-const-or-ref-data-members)

    Counter(int& v) : value(v) { }

    ~Counter() { value++; }
};

auto some_function() -> void { }
} // namespace

template <typename T>
auto test() -> bool
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
        CHECK(etl::addressof(some_function) == &some_function);
    }
    {
        alignas(Counter) etl::byte buffer[sizeof(Counter) * 8];

        auto counter = 0;
        for (auto i = 0U; i < 8; ++i) {
            new (buffer + sizeof(Counter) * i) Counter{counter};
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
            new (buffer + sizeof(Counter) * i) Counter{counter};
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
            new (&buffer[0] + sizeof(Counter) * i) Counter{counter};
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

#else
auto main() -> int { return 0; }
#endif
