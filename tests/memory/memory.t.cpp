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
        auto* ptr    = ::new T {};
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
        assert(etl::addressof(val) == &val);
        assert(etl::addressof(some_function) == &some_function);
    }
    {
        alignas(Counter) etl::byte buffer[sizeof(Counter) * 8];

        auto counter = 0;
        for (auto i = 0U; i < 8; ++i) { new (buffer + sizeof(Counter) * i) Counter {counter}; }
        assert(counter == 0);

        auto* ptr = reinterpret_cast<Counter*>(&buffer[0]);
        for (auto i = 0U; i < 8; ++i) { etl::destroy_at(ptr + i); }

        assert(counter == 8);
    }

    {
        alignas(Counter) etl::byte buffer[sizeof(Counter) * 8];

        auto counter = 0;
        for (auto i = 0U; i < 8; ++i) { new (buffer + sizeof(Counter) * i) Counter {counter}; }
        assert(counter == 0);

        auto* ptr = reinterpret_cast<Counter*>(&buffer[0]);
        etl::destroy(ptr, ptr + 8);

        assert(counter == 8);
    }

    {
        alignas(Counter) etl::byte buffer[sizeof(Counter) * 8];

        auto counter = 0;
        for (auto i = 0U; i < 8; ++i) { new (&buffer[0] + sizeof(Counter) * i) Counter {counter}; }
        assert(counter == 0);

        auto* ptr = reinterpret_cast<Counter*>(&buffer[0]);
        etl::destroy_n(ptr, 4);

        assert(counter == 4);
    }

    {
        auto foo = T(1);
        assert((etl::assume_aligned<alignof(T), T>(&foo) == &foo));
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

#else
auto main() -> int { return 0; }
#endif
