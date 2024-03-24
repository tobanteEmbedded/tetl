// SPDX-License-Identifier: BSL-1.0

#include <etl/vector.hpp>

#include <etl/concepts.hpp>
#include <etl/memory.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

template <typename T>
constexpr auto test() -> bool
{
    using Alloc  = etl::monotonic_allocator<T>;
    using Vector = etl::vector<T, Alloc>;

    CHECK_SAME_TYPE(typename Vector::value_type, T);
    CHECK_SAME_TYPE(typename Vector::allocator_type, Alloc);
    CHECK_SAME_TYPE(typename Vector::size_type, etl::size_t);
    CHECK_SAME_TYPE(typename Vector::difference_type, etl::ptrdiff_t);
    CHECK_SAME_TYPE(typename Vector::pointer, T*);
    CHECK_SAME_TYPE(typename Vector::const_pointer, T const*);

    {
        auto memory = etl::array<etl::byte, 64>{};
        auto empty  = Vector{Alloc{memory}};
        CHECK(empty.size() == 0);
        CHECK(etl::as_const(empty).size() == 0);
        CHECK(empty.data() == nullptr);
        CHECK(etl::as_const(empty).data() == nullptr);
        CHECK(empty.begin() == nullptr);
        CHECK(etl::as_const(empty).begin() == nullptr);
        CHECK(empty.end() == nullptr);
        CHECK(etl::as_const(empty).end() == nullptr);
    }

    {
        auto memory = etl::array<etl::byte, 64>{};
        auto zeros  = Vector{2, Alloc{memory}};
        CHECK(zeros.size() == 2);
        CHECK(etl::as_const(zeros).size() == 2);
        CHECK(zeros.data() != nullptr);
        CHECK(etl::as_const(zeros).data() != nullptr);
        CHECK(zeros.begin() != nullptr);
        CHECK(etl::as_const(zeros).begin() != nullptr);
        CHECK(zeros.end() != nullptr);
        CHECK(etl::as_const(zeros).end() != nullptr);
    }

    {
        auto memory = etl::array<etl::byte, 64>{};
        auto ones   = Vector{4, T(1), Alloc{memory}};
        CHECK(ones.size() == 4);
        CHECK(etl::as_const(ones).size() == 4);
        CHECK(ones.data() != nullptr);
        CHECK(etl::as_const(ones).data() != nullptr);
        CHECK(ones.begin() != nullptr);
        CHECK(etl::as_const(ones).begin() != nullptr);
        CHECK(ones.end() != nullptr);
        CHECK(etl::as_const(ones).end() != nullptr);
    }

    return true;
}

constexpr auto test_all() -> bool
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
