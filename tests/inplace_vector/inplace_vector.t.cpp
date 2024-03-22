// SPDX-License-Identifier: BSL-1.0

#include <etl/inplace_vector.hpp>

#include <etl/type_traits.hpp>
#include <etl/utility.hpp>

#include "testing/testing.hpp"

namespace {

template <typename T, typename Vector>
constexpr auto test_typedefs() -> bool
{
    CHECK_SAME_TYPE(typename Vector::value_type, T);
    CHECK_SAME_TYPE(typename Vector::size_type, etl::size_t);
    CHECK_SAME_TYPE(typename Vector::difference_type, etl::ptrdiff_t);
    CHECK_SAME_TYPE(typename Vector::pointer, T*);
    CHECK_SAME_TYPE(typename Vector::const_pointer, T const*);
    CHECK_SAME_TYPE(typename Vector::iterator, T*);
    CHECK_SAME_TYPE(typename Vector::const_iterator, T const*);
    CHECK_SAME_TYPE(typename Vector::reverse_iterator, etl::reverse_iterator<T*>);
    CHECK_SAME_TYPE(typename Vector::const_reverse_iterator, etl::reverse_iterator<T const*>);
    CHECK_SAME_TYPE(typename Vector::reference, T&);
    CHECK_SAME_TYPE(typename Vector::const_reference, T const&);

    auto vec = Vector();
    CHECK_SAME_TYPE(decltype(vec.empty()), bool);
    CHECK_SAME_TYPE(decltype(vec.size()), etl::size_t);
    CHECK_SAME_TYPE(decltype(vec.capacity()), etl::size_t);
    CHECK_SAME_TYPE(decltype(vec.max_size()), etl::size_t);
    CHECK_SAME_TYPE(decltype(vec.data()), T*);
    CHECK_SAME_TYPE(decltype(etl::as_const(vec).data()), T const*);
    CHECK_SAME_TYPE(decltype(vec.begin()), T*);
    CHECK_SAME_TYPE(decltype(etl::as_const(vec).begin()), T const*);
    CHECK_SAME_TYPE(decltype(vec.end()), T*);
    CHECK_SAME_TYPE(decltype(etl::as_const(vec).end()), T const*);

    CHECK_NOEXCEPT(vec.empty());
    CHECK_NOEXCEPT(vec.size());
    CHECK_NOEXCEPT(vec.capacity());
    CHECK_NOEXCEPT(vec.max_size());
    CHECK_NOEXCEPT(vec.data());
    CHECK_NOEXCEPT(etl::as_const(vec).data());
    CHECK_NOEXCEPT(vec.begin());
    CHECK_NOEXCEPT(etl::as_const(vec).begin());
    CHECK_NOEXCEPT(vec.end());
    CHECK_NOEXCEPT(etl::as_const(vec).end());

    return true;
}

template <typename T>
constexpr auto test_empty() -> bool
{
    using Vector0 = etl::inplace_vector<T, 0>;
    CHECK(test_typedefs<T, Vector0>());
    CHECK(etl::is_empty_v<Vector0>);
    CHECK(etl::is_trivial_v<Vector0>);
    CHECK(Vector0().empty());
    CHECK(Vector0().size() == 0);
    CHECK(Vector0().capacity() == 0);
    CHECK(Vector0().max_size() == 0);
    CHECK(Vector0().data() == nullptr);
    CHECK(Vector0().begin() == nullptr);
    CHECK(Vector0().end() == nullptr);
    CHECK(Vector0().data() == Vector0().data());
    return true;
}

template <typename T, etl::size_t Size>
constexpr auto test_non_empty() -> bool
{
    using Vector = etl::inplace_vector<T, Size>;
    CHECK_FALSE(etl::is_empty_v<Vector>);
    CHECK(test_typedefs<T, Vector>());
    CHECK(etl::is_trivially_copy_constructible_v<Vector> == etl::is_trivially_copy_constructible_v<T>);
    CHECK(etl::is_trivially_move_constructible_v<Vector> == etl::is_trivially_move_constructible_v<T>);
    CHECK(etl::is_trivially_destructible_v<Vector> == etl::is_trivially_destructible_v<T>);
    CHECK(Vector().empty());
    CHECK(Vector().size() == 0);
    CHECK(Vector().capacity() == Size);
    CHECK(Vector().max_size() == Size);
    CHECK(Vector().data() != nullptr);
    CHECK(Vector().begin() != nullptr);
    CHECK(Vector().end() != nullptr);
    CHECK(Vector().data() != Vector().data());
    return true;
}

template <typename T>
    requires etl::is_trivial_v<T>
constexpr auto test_trivial() -> bool
{
    CHECK(test_empty<T>());
    CHECK(test_non_empty<T, 1>());
    CHECK(test_non_empty<T, 4>());
    return true;
}

constexpr auto test_cx() -> bool
{
    CHECK(test_trivial<signed char>());
    CHECK(test_trivial<signed short>());
    CHECK(test_trivial<signed int>());
    CHECK(test_trivial<signed long>());
    CHECK(test_trivial<signed long long>());

    CHECK(test_trivial<unsigned char>());
    CHECK(test_trivial<unsigned short>());
    CHECK(test_trivial<unsigned int>());
    CHECK(test_trivial<unsigned long>());
    CHECK(test_trivial<unsigned long long>());

    CHECK(test_trivial<char>());
    CHECK(test_trivial<char8_t>());
    CHECK(test_trivial<char16_t>());
    CHECK(test_trivial<char32_t>());
    CHECK(test_trivial<wchar_t>());

    CHECK(test_trivial<float>());
    CHECK(test_trivial<double>());
    CHECK(test_trivial<long double>());

    return true;
}

auto test_non_trivial() -> bool
{
    struct non_trivial {
        non_trivial() { }

        ~non_trivial() { }

        non_trivial(non_trivial const& /*other*/) { }

        non_trivial(non_trivial&& /*other*/) { }

        auto operator=(non_trivial const& /*other*/) -> non_trivial& { return *this; }

        auto operator=(non_trivial&& /*other*/) -> non_trivial& { return *this; }
    };

    CHECK_FALSE(etl::is_trivial_v<non_trivial>);
    CHECK(test_empty<non_trivial>());
    CHECK(test_non_empty<non_trivial, 1>());
    CHECK(test_non_empty<non_trivial, 4>());

    auto empty      = etl::inplace_vector<non_trivial, 4>{};
    auto const copy = empty;
    auto const move = etl::move(empty);
    CHECK(empty.empty()); // NOLINT
    CHECK(copy.empty());
    CHECK(move.empty());

    return true;
}
} // namespace

auto main() -> int
{
    STATIC_CHECK(test_cx());
    CHECK(test_non_trivial());
    return 0;
}
