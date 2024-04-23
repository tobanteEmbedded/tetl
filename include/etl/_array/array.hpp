// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ARRAY_ARRAY_HPP
#define TETL_ARRAY_ARRAY_HPP

#include <etl/_config/all.hpp>

#include <etl/_algorithm/equal.hpp>
#include <etl/_algorithm/fill_n.hpp>
#include <etl/_algorithm/lexicographical_compare.hpp>
#include <etl/_algorithm/swap_ranges.hpp>
#include <etl/_array/c_array.hpp>
#include <etl/_contracts/check.hpp>
#include <etl/_cstddef/size_t.hpp>
#include <etl/_iterator/begin.hpp>
#include <etl/_iterator/data.hpp>
#include <etl/_iterator/end.hpp>
#include <etl/_iterator/prev.hpp>
#include <etl/_iterator/rbegin.hpp>
#include <etl/_iterator/rend.hpp>
#include <etl/_iterator/reverse_iterator.hpp>
#include <etl/_iterator/size.hpp>
#include <etl/_tuple/is_tuple_like.hpp>
#include <etl/_tuple/tuple_element.hpp>
#include <etl/_tuple/tuple_size.hpp>
#include <etl/_type_traits/conditional.hpp>
#include <etl/_type_traits/is_nothrow_swappable.hpp>
#include <etl/_type_traits/remove_cv.hpp>
#include <etl/_utility/index_sequence.hpp>
#include <etl/_utility/move.hpp>
#include <etl/_utility/unreachable.hpp>

namespace etl {
/// A container that encapsulates fixed size arrays.
///
/// This container is an aggregate type with the same semantics as a
/// struct holding a C-style array Type[N] as its only non-static data member.
/// Unlike a C-style array, it doesn't decay to Type* automatically. As an
/// aggregate type, it can be initialized with aggregate-initialization given at
/// most N initializers that are convertible to
/// Type: `array<int, 3> a = {1,2,3};`
///
/// \include array.cpp
///
/// \headerfile etl/array.hpp
/// \ingroup array
template <typename Type, size_t Size>
struct array {
    using value_type             = Type;
    using size_type              = size_t;
    using difference_type        = ptrdiff_t;
    using pointer                = Type*;
    using const_pointer          = Type const*;
    using reference              = Type&;
    using const_reference        = Type const&;
    using iterator               = Type*;
    using const_iterator         = Type const*;
    using reverse_iterator       = typename etl::reverse_iterator<iterator>;
    using const_reverse_iterator = typename etl::reverse_iterator<const_iterator>;

    /// Accesses the specified item with range checking.
    [[nodiscard]] constexpr auto operator[](size_type const pos) noexcept -> reference
    {
        if constexpr (Size == 0) {
            etl::unreachable();
        } else {
            TETL_PRECONDITION_SAFE(pos < Size);
            return _buf[pos];
        }
    }

    /// Accesses the specified item with range checking.
    [[nodiscard]] constexpr auto operator[](size_type const pos) const noexcept -> const_reference
    {
        if constexpr (Size == 0) {
            etl::unreachable();
        } else {
            TETL_PRECONDITION_SAFE(pos < Size);
            return _buf[pos];
        }
    }

    /// Accesses the first item.
    [[nodiscard]] constexpr auto front() noexcept -> reference { return *begin(); }

    /// Accesses the first item.
    [[nodiscard]] constexpr auto front() const noexcept -> const_reference { return *begin(); }

    /// Accesses the last item.
    [[nodiscard]] constexpr auto back() noexcept -> reference { return *etl::prev(end()); }

    /// Accesses the last item.
    [[nodiscard]] constexpr auto back() const noexcept -> const_reference { return *etl::prev(end()); }

    /// Returns pointer to the underlying array serving as element
    /// storage. The pointer is such that range [data(); data() + size()) is
    /// always a valid range, even if the container is empty (data() is not
    /// dereferenceable in that case).
    [[nodiscard]] constexpr auto data() noexcept -> pointer { return begin(); }

    /// Returns pointer to the underlying array serving as element
    /// storage. The pointer is such that range [data(); data() + size()) is
    /// always a valid range, even if the container is empty (data() is not
    /// dereferenceable in that case).
    [[nodiscard]] constexpr auto data() const noexcept -> const_pointer { return begin(); }

    /// Returns an iterator to the beginning.
    [[nodiscard]] constexpr auto begin() noexcept -> iterator
    {
        if constexpr (Size == 0) {
            return nullptr;
        } else {
            return etl::begin(_buf);
        }
    }

    /// Returns an iterator to the beginning.
    [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator
    {
        if constexpr (Size == 0) {
            return nullptr;
        } else {
            return etl::begin(_buf);
        }
    }

    /// Returns an const iterator to the beginning.
    [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator { return begin(); }

    /// Returns an iterator to the end.
    [[nodiscard]] constexpr auto end() noexcept -> iterator
    {
        if constexpr (Size == 0) {
            return nullptr;
        } else {
            return etl::end(_buf);
        }
    }

    /// Returns an iterator to the end.
    [[nodiscard]] constexpr auto end() const noexcept -> const_iterator
    {
        if constexpr (Size == 0) {
            return nullptr;
        } else {
            return etl::end(_buf);
        }
    }

    /// Returns an const iterator to the end.
    [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator { return end(); }

    /// Returns a reverse iterator to the first element of the reversed
    /// array. It corresponds to the last element of the non-reversed array. If
    /// the array is empty, the returned iterator is equal to rend().
    [[nodiscard]] constexpr auto rbegin() noexcept -> reverse_iterator { return reverse_iterator(end()); }

    /// Returns a reverse iterator to the first element of the reversed
    /// array. It corresponds to the last element of the non-reversed array. If
    /// the array is empty, the returned iterator is equal to rend().
    [[nodiscard]] constexpr auto rbegin() const noexcept -> const_reverse_iterator
    {
        return const_reverse_iterator(end());
    }

    /// Returns a reverse iterator to the first element of the reversed
    /// array. It corresponds to the last element of the non-reversed array. If
    /// the array is empty, the returned iterator is equal to rend().
    [[nodiscard]] constexpr auto crbegin() const noexcept -> const_reverse_iterator { return rbegin(); }

    /// Returns a reverse iterator to the element following the last
    /// element of the reversed array. It corresponds to the element preceding
    /// the first element of the non-reversed array. This element acts as a
    /// placeholder, attempting to access it results in undefined behavior.
    [[nodiscard]] constexpr auto rend() noexcept -> reverse_iterator { return reverse_iterator(begin()); }

    /// Returns a reverse iterator to the element following the last
    /// element of the reversed array. It corresponds to the element preceding
    /// the first element of the non-reversed array. This element acts as a
    /// placeholder, attempting to access it results in undefined behavior.
    [[nodiscard]] constexpr auto rend() const noexcept -> const_reverse_iterator
    {
        return const_reverse_iterator(begin());
    }

    /// Returns a reverse iterator to the element following the last
    /// element of the reversed array. It corresponds to the element preceding
    /// the first element of the non-reversed array. This element acts as a
    /// placeholder, attempting to access it results in undefined behavior.
    [[nodiscard]] constexpr auto crend() const noexcept -> const_reverse_iterator { return rend(); }

    /// Checks if the container has no elements, i.e. whether begin() == end().
    [[nodiscard]] constexpr auto empty() const noexcept -> bool { return begin() == end(); }

    /// Returns the number of elements in the container, i.e. distance(begin(), end()).
    [[nodiscard]] constexpr auto size() const noexcept -> size_type { return Size; }

    /// Returns the maximum number of elements the container is able to
    /// hold due to system or library implementation limitations, i.e.
    /// distance(begin(), end()) for the largest container.
    ///
    /// Because each array<T, N> is a fixed-size container, the value
    /// returned by max_size equals N (which is also the value returned by size)
    [[nodiscard]] constexpr auto max_size() const noexcept -> size_type { return Size; }

    /// Assigns the given value value to all elements in the container.
    constexpr auto fill(const_reference value) -> void { etl::fill_n(begin(), Size, value); }

    /// Exchanges the contents of the container with those of other. Does
    /// not cause iterators and references to associate with the other
    /// container.
    constexpr auto swap(array& other) noexcept(is_nothrow_swappable_v<Type>) -> void
    {
        etl::swap_ranges(begin(), end(), other.begin());
    }

    /// Specializes the swap algorithm for array. Swaps the contents of lhs and rhs.
    friend constexpr auto swap(array& lhs, array& rhs) noexcept(noexcept(lhs.swap(rhs))) -> void { lhs.swap(rhs); }

    /// Checks if the contents of lhs and rhs are equal, that is, they have
    /// the same number of elements and each element in lhs compares equal with the
    /// element in rhs at the same position.
    friend constexpr auto operator==(array const& lhs, array const& rhs) -> bool
    {
        return etl::equal(lhs.begin(), lhs.end(), rhs.begin());
    }

    /// Compares the contents of lhs and rhs lexicographically. The
    /// comparison is performed by a function equivalent to lexicographical_compare.
    friend constexpr auto operator<(array const& lhs, array const& rhs) -> bool
    {
        return etl::lexicographical_compare(lhs.begin(), lhs.end(), rhs.begin(), rhs.end());
    }

    friend constexpr auto operator<=(array const& lhs, array const& rhs) -> bool { return !(rhs < lhs); }

    friend constexpr auto operator>(array const& lhs, array const& rhs) -> bool { return rhs < lhs; }

    friend constexpr auto operator>=(array const& lhs, array const& rhs) -> bool { return !(lhs < rhs); }

    /// \internal
    // NOLINTNEXTLINE(readability-identifier-naming)
    TETL_NO_UNIQUE_ADDRESS conditional_t<Size == 0, empty_c_array, c_array<Type, Size + size_t{Size == 0}>> _buf;
};

/// One deduction guide is provided for array to provide an equivalent of
/// experimental::make_array for construction of array from a variadic parameter
/// pack. The program is ill-formed if (is_same_v<T, U> and ...) is not true.
/// Note that it is true when sizeof...(U) is zero.
/// \relates array
template <typename T, typename... U>
array(T, U...) -> array<T, 1 + sizeof...(U)>;

/// \brief Provides access to the number of elements in an array as a
/// compile-time constant expression.
/// \relates array
template <typename T, size_t N>
struct tuple_size<array<T, N>> : integral_constant<size_t, N> { };

/// \relates array
template <typename T, etl::size_t Size>
inline constexpr auto is_tuple_like<etl::array<T, Size>> = true;

/// \brief Provides compile-time indexed access to the type of the elements of
/// the array using tuple-like interface.
template <size_t I, typename T>
struct tuple_element;

template <size_t I, typename T, size_t N>
struct tuple_element<I, array<T, N>> {
    using type = T;
};

/// \brief Extracts the Ith element element from the array. I must be an integer
/// value in range [0, N). This is enforced at compile time as opposed to at()
/// or operator[].
/// \relates array
template <size_t Index, typename T, size_t Size>
[[nodiscard]] constexpr auto get(array<T, Size>& array) noexcept -> T&
{
    static_assert(Index < Size, "array index out of range");
    return array[Index];
}

/// \relates array
template <size_t Index, typename T, size_t Size>
[[nodiscard]] constexpr auto get(array<T, Size> const& array) noexcept -> T const&
{
    static_assert(Index < Size, "array index out of range");
    return array[Index];
}

/// \relates array
template <size_t Index, typename T, size_t Size>
[[nodiscard]] constexpr auto get(array<T, Size>&& array) noexcept -> T&&
{
    static_assert(Index < Size, "array index out of range");
    return etl::move(array[Index]);
}

/// \relates array
template <size_t Index, typename T, size_t Size>
[[nodiscard]] constexpr auto get(array<T, Size> const&& array) noexcept -> T const&&
{
    static_assert(Index < Size, "array index out of range");
    return etl::move(array[Index]);
}

/// \brief Creates a array from the one dimensional built-in array a. The
/// elements of the array are copy-initialized from the corresponding element of
/// a. Copying or moving multidimensional built-in array is not supported.
/// \relates array
template <typename T, size_t N>
[[nodiscard]] constexpr auto to_array(T (&a)[N]) -> array<remove_cv_t<T>, N>
{
    return [&]<etl::size_t... I>(etl::index_sequence<I...> /*i*/) {
        return etl::array<etl::remove_cv_t<T>, N>{{a[I]...}};
    }(etl::make_index_sequence<N>{});
}

/// \relates array
template <typename T, size_t N>
[[nodiscard]] constexpr auto to_array(T (&&a)[N])
{
    return [&]<etl::size_t... I>(etl::index_sequence<I...> /*i*/) {
        return etl::array<etl::remove_cv_t<T>, N>{{etl::move(a[I])...}};
    }(etl::make_index_sequence<N>{});
}

} // namespace etl

#endif // TETL_ARRAY_ARRAY_HPP
