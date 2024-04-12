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
    CHECK_SAME_TYPE(decltype(vec.size()), typename Vector::size_type);
    CHECK_SAME_TYPE(decltype(vec.capacity()), typename Vector::size_type);
    CHECK_SAME_TYPE(decltype(vec.max_size()), typename Vector::size_type);
    CHECK_SAME_TYPE(decltype(vec.data()), typename Vector::pointer);
    CHECK_SAME_TYPE(decltype(etl::as_const(vec).data()), typename Vector::const_pointer);
    CHECK_SAME_TYPE(decltype(vec.begin()), typename Vector::iterator);
    CHECK_SAME_TYPE(decltype(etl::as_const(vec).begin()), typename Vector::const_iterator);
    CHECK_SAME_TYPE(decltype(vec.end()), typename Vector::iterator);
    CHECK_SAME_TYPE(decltype(etl::as_const(vec).end()), typename Vector::const_iterator);

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
    CHECK_NOEXCEPT(vec.clear());

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

    auto vec = Vector0{};
    CHECK(vec.empty());
    CHECK(vec.try_emplace_back(T(0)) == nullptr);
    CHECK(vec.empty());
    CHECK(vec.try_push_back(T(0)) == nullptr);
    CHECK(vec.empty());
    CHECK_NOEXCEPT(vec.clear());
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

    auto vec  = Vector{};
    auto* ptr = vec.try_emplace_back(T(1));
    CHECK(ptr != nullptr);
    CHECK(*ptr == T(1));
    CHECK(vec.size() == 1);
    CHECK(vec[0] == vec.front());
    CHECK(etl::as_const(vec)[0] == etl::as_const(vec).front());
    CHECK(vec.front() == vec.back());
    CHECK(etl::as_const(vec).front() == etl::as_const(vec).back());
    CHECK_FALSE(vec.empty());

    auto const wasFull = vec.size() == vec.capacity();

    auto* push = vec.try_push_back(T(0));
    CHECK((push == nullptr) == wasFull);

    auto const oldSize = vec.size();
    vec.pop_back();
    CHECK(vec.size() == oldSize - 1);

    vec.clear();
    CHECK(vec.empty());

    auto one = etl::inplace_vector<T, 1>{};
    CHECK(one.unchecked_push_back(T(0)) == T(0));
    CHECK(one.try_push_back(T(1)) == nullptr);

    one.clear();
    CHECK(one.unchecked_emplace_back(T(0)) == T(0));
    CHECK(one.try_emplace_back(T(1)) == nullptr);

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

struct non_trivial {
    constexpr non_trivial() = default;

    explicit constexpr non_trivial(int val)
        : value{val}
    {
    }

    constexpr ~non_trivial() { } // NOLINT

    constexpr non_trivial(non_trivial const& other)
        : value{other.value}
    {
    }

    constexpr non_trivial(non_trivial&& other)
        : value{other.value}
    {
    }

    constexpr auto operator=(non_trivial const& other) -> non_trivial&
    {
        value = other.value;
        return *this;
    }

    constexpr auto operator=(non_trivial&& other) -> non_trivial&
    {
        value = other.value;
        return *this;
    }

    friend constexpr auto operator==(non_trivial const& lhs, non_trivial const& rhs) -> bool
    {
        return lhs.value == rhs.value;
    }

    int value{0};
};

auto test_non_trivial() -> bool
{
    CHECK(test_empty<non_trivial>());
    CHECK_FALSE(etl::is_trivial_v<non_trivial>);

    auto vec        = etl::inplace_vector<non_trivial, 3>{};
    auto* const p42 = vec.try_emplace_back(42);
    CHECK(p42 != nullptr);
    CHECK(p42->value == 42);
    CHECK(vec.size() == 1);
    CHECK(vec[0] == vec.front());
    CHECK(vec.front() == vec.back());

    auto move = etl::move(vec);
    CHECK_FALSE(move.empty());
    CHECK(vec.empty()); // NOLINT

    auto* const p143 = move.try_push_back(non_trivial{143});
    CHECK(p143 != nullptr);
    CHECK(p143->value == 143);
    CHECK(move.size() == 2);
    CHECK(move[0] == move.front());
    CHECK(move[1] == move.back());
    CHECK(move.front() != move.back());

    auto const nt99 = non_trivial{99};
    auto* const p99 = move.try_push_back(nt99);
    CHECK(p99 != nullptr);
    CHECK(p99->value == 99);
    CHECK(move.size() == 3);
    CHECK(move[0] == move.front());
    CHECK(move[2] == move.back());
    CHECK(move.front() != move.back());

    CHECK(move.try_emplace_back(nt99) == nullptr);
    CHECK(move.size() == 3);

    CHECK(move.try_push_back(nt99) == nullptr);
    CHECK(move.size() == 3);

    CHECK(move.try_push_back(non_trivial{42}) == nullptr);
    CHECK(move.size() == 3);

    move.pop_back();
    move.pop_back();
    CHECK(move.size() == 1);
    CHECK(move[0] == move.front());
    CHECK(move.front() == move.back());

    move.clear();
    CHECK_NOEXCEPT(move.clear());
    CHECK(move.empty());

    auto one = non_trivial{1};
    CHECK(move.unchecked_push_back(etl::move(one)) == non_trivial{1});

    return true;
}
} // namespace

auto main() -> int
{
    STATIC_CHECK(test_cx());
    CHECK(test_non_trivial());
    return 0;
}
