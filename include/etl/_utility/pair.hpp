// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_UTILITY_PAIR_HPP
#define TETL_UTILITY_PAIR_HPP

#include <etl/_tuple/is_tuple_like.hpp>
#include <etl/_tuple/tuple_element.hpp>
#include <etl/_tuple/tuple_size.hpp>
#include <etl/_type_traits/common_reference.hpp>
#include <etl/_type_traits/decay.hpp>
#include <etl/_type_traits/integral_constant.hpp>
#include <etl/_type_traits/is_assignable.hpp>
#include <etl/_type_traits/is_constructible.hpp>
#include <etl/_type_traits/is_convertible.hpp>
#include <etl/_type_traits/is_copy_constructible.hpp>
#include <etl/_type_traits/is_default_constructible.hpp>
#include <etl/_type_traits/is_implicit_default_constructible.hpp>
#include <etl/_type_traits/is_move_assignable.hpp>
#include <etl/_type_traits/is_nothrow_swappable.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/move.hpp>
#include <etl/_utility/swap.hpp>

namespace etl {

/// \brief etl::pair is a class template that provides a way to store two
/// heterogeneous objects as a single unit. A pair is a specific case of a
/// etl::tuple with two elements. If neither T1 nor T2 is a possibly
/// cv-qualified class type with non-trivial destructor, or array thereof, the
/// destructor of pair is trivial.
///
/// https://en.cppreference.com/w/cpp/utility/pair
template <typename T1, typename T2>
struct pair {
    using first_type  = T1;
    using second_type = T2;

    /// \brief Default constructor. Value-initializes both elements.
    explicit(not is_implicit_default_constructible_v<T1> || not is_implicit_default_constructible_v<T2>) constexpr pair(
    )
        requires(is_default_constructible_v<T1> and is_default_constructible_v<T2>)
        : first{}
        , second{}
    {
    }

    /// \brief Initializes first with x and second with y.
    explicit(not is_convertible_v<T1 const&, T1> or not is_convertible_v<T2 const&, T2>) constexpr pair(
        T1 const& t1,
        T2 const& t2
    )
        requires(is_copy_constructible_v<T1> and is_copy_constructible_v<T2>)
        : first(t1)
        , second(t2)
    {
    }

    /// \brief Initializes first with forward<U1>(x) and second with forward<U2>(y).
    template <typename U1 = T1, typename U2 = T2>
        requires(is_constructible_v<T1, U1 &&> and is_constructible_v<T2, U2 &&>)
    explicit(not is_convertible_v<U1&&, T1> || not is_convertible_v<U2&&, T2>) constexpr pair(U1&& x, U2&& y)
        : first(etl::forward<U1>(x))
        , second(etl::forward<U2>(y))
    {
    }

    /// \brief Initializes first with p.first and second with p.second.
    template <typename U1, typename U2>
        requires(is_constructible_v<T1, U1 const&> and is_constructible_v<T2, U2 const&>)
    explicit(not is_convertible_v<U1 const&, T1> or not is_convertible_v<U2 const&, T2>) constexpr pair(
        pair<U1, U2> const& p
    )
        : first(p.first)
        , second(p.second)
    {
    }

    /// \brief Initializes first with forward<U1>(p.first) and second with forward<U2>(p.second).
    template <typename U1, typename U2>
        requires(is_constructible_v<T1, U1 &&> and is_constructible_v<T2, U2 &&>)
    explicit(not is_convertible_v<U1&&, T1> || not is_convertible_v<U2&&, T2>) constexpr pair(pair<U1, U2>&& p)
        : first(etl::forward<U1>(p.first))
        , second(etl::forward<U2>(p.second))
    {
    }

    /// \brief Copy constructor is defaulted, and is constexpr if copying of
    /// both elements satisfies the requirements on constexpr functions.
    constexpr pair(pair const& p) = default;

    /// \brief Move constructor is defaulted, and is constexpr if moving of both
    /// elements satisfies the requirements on constexpr functions.
    constexpr pair(pair&& p) noexcept = default;

    /// \brief Defaulted destructor.
    ~pair() noexcept = default;

    constexpr auto operator=(pair const& p) -> pair&
    {
        if (&p == this) {
            return *this;
        }
        first  = p.first;
        second = p.second;
        return *this;
    }

    template <typename U1, typename U2>
    constexpr auto operator=(pair<U1, U2> const& p
    ) -> pair& requires(is_assignable_v<first_type&, U1 const&>and is_assignable_v<second_type&, U2 const&>) {
        first  = p.first;
        second = p.second;
        return *this;
    }

    constexpr auto operator=(pair&& p
    ) noexcept -> pair& requires(is_move_assignable_v<first_type>and is_move_assignable_v<second_type>) {
        first  = etl::move(p.first);
        second = etl::move(p.second);
        return *this;
    }

    template <typename U1, typename U2>
        requires(is_assignable_v<first_type&, U1> and is_assignable_v<second_type&, U2>)
    constexpr auto operator=(pair<U1, U2>&& p) -> pair&
    {
        first  = etl::move(p.first);
        second = etl::move(p.second);
        return *this;
    }

    constexpr void swap(pair& other
    ) noexcept((is_nothrow_swappable_v<first_type> and is_nothrow_swappable_v<second_type>))
    {
        using etl::swap;
        swap(first, other.first);
        swap(second, other.second);
    }

    TETL_NO_UNIQUE_ADDRESS T1 first;  // NOLINT
    TETL_NO_UNIQUE_ADDRESS T2 second; // NOLINT

}; // namespace etl

// One deduction guide is provided for pair to account for the edge
// cases missed by the implicit deduction guides. In particular, non-copyable
// arguments and array to pointer conversion.
template <typename T1, typename T2>
pair(T1, T2) -> pair<T1, T2>;

template <typename T, typename U>
inline constexpr auto is_tuple_like<etl::pair<T, U>> = true;

/// \brief Swaps the contents of x and y. Equivalent to x.swap(y).
template <typename T1, typename T2>
constexpr auto swap(pair<T1, T2>& lhs, pair<T1, T2>& rhs) noexcept(noexcept(lhs.swap(rhs))) -> void
{
    lhs.swap(rhs);
}

/// \brief Creates a etl::pair object, deducing the target type from the types
/// of arguments.
///
/// \details The deduced types V1 and V2 are etl::decay<T1>::type and
/// etl::decay<T2>::type (the usual type transformations applied to arguments of
/// functions passed by value).
///
/// https://en.cppreference.com/w/cpp/utility/pair/make_pair
template <typename T1, typename T2>
[[nodiscard]] constexpr auto make_pair(T1&& t, T2&& u) -> pair<decay_t<T1>, decay_t<T2>>
{
    return {etl::forward<T1>(t), etl::forward<T2>(u)};
}

/// \brief Tests if both elements of lhs and rhs are equal, that is, compares
/// lhs.first with rhs.first and lhs.second with rhs.second.
template <typename T1, typename T2>
constexpr auto operator==(pair<T1, T2> const& lhs, pair<T1, T2> const& rhs) -> bool
{
    return (lhs.first == rhs.first) and (lhs.second == rhs.second);
}

/// \brief Compares lhs and rhs lexicographically by operator<, that is,
/// compares the first elements and only if they are equivalent, compares the
/// second elements.
template <typename T1, typename T2>
constexpr auto operator<(pair<T1, T2> const& lhs, pair<T1, T2> const& rhs) -> bool
{
    if (lhs.first < rhs.first) {
        return true;
    }
    if (rhs.first < lhs.first) {
        return false;
    }
    if (lhs.second < rhs.second) {
        return true;
    }
    return false;
}

/// \brief Compares lhs and rhs lexicographically by operator<, that is,
/// compares the first elements and only if they are equivalent, compares the
/// second elements.
template <typename T1, typename T2>
constexpr auto operator<=(pair<T1, T2> const& lhs, pair<T1, T2> const& rhs) -> bool
{
    return !(rhs < lhs);
}

/// \brief Compares lhs and rhs lexicographically by operator<, that is,
/// compares the first elements and only if they are equivalent, compares the
/// second elements.
template <typename T1, typename T2>
constexpr auto operator>(pair<T1, T2> const& lhs, pair<T1, T2> const& rhs) -> bool
{
    return rhs < lhs;
}

/// \brief Compares lhs and rhs lexicographically by operator<, that is,
/// compares the first elements and only if they are equivalent, compares the
/// second elements.
template <typename T1, typename T2>
constexpr auto operator>=(pair<T1, T2> const& lhs, pair<T1, T2> const& rhs) -> bool
{
    return !(lhs < rhs);
}

/// \brief The partial specialization of tuple_size for pairs provides a
/// compile-time way to obtain the number of elements in a pair, which is always
/// 2, using tuple-like syntax.
template <typename T1, typename T2>
struct tuple_size<pair<T1, T2>> : integral_constant<size_t, 2> { };

/// \brief The partial specializations of tuple_element for pairs provide
/// compile-time access to the types of the pair's elements, using tuple-like
/// syntax. The program is ill-formed if I >= 2.
template <size_t I, typename T1, typename T2>
struct tuple_element<I, pair<T1, T2>> {
    static_assert(I < 2, "pair index out of range");
    using type = conditional_t<I == 0, T1, T2>;
};

/// \brief Extracts an element from the pair using tuple-like interface.
///
/// \details The index-based overloads (1-4) fail to compile if the index I is
/// neither 0 nor 1. See Alisdar Meredith talk "Recreational C++" 35:00 to
/// 46:00. https://youtu.be/ovxNM865WaU
template <size_t I, typename T1, typename T2>
constexpr auto get(pair<T1, T2>& p) noexcept -> tuple_element_t<I, pair<T1, T2>>&
{
    if constexpr (I == 0) {
        return p.first;
    } else {
        return p.second;
    }
}

/// \brief Extracts an element from the pair using tuple-like interface.
///
/// \details The index-based overloads (1-4) fail to compile if the index I is
/// neither 0 nor 1. See Alisdar Meredith talk "Recreational C++" 35:00 to
/// 46:00. https://youtu.be/ovxNM865WaU
template <size_t I, typename T1, typename T2>
[[nodiscard]] constexpr auto get(pair<T1, T2> const& p) noexcept -> tuple_element_t<I, pair<T1, T2>> const&
{
    if constexpr (I == 0) {
        return p.first;
    } else {
        return p.second;
    }
}

/// \brief Extracts an element from the pair using tuple-like interface.
///
/// \details The index-based overloads (1-4) fail to compile if the index I is
/// neither 0 nor 1. See Alisdar Meredith talk "Recreational C++" 35:00 to
/// 46:00. https://youtu.be/ovxNM865WaU
template <size_t I, typename T1, typename T2>
[[nodiscard]] constexpr auto get(pair<T1, T2>&& p) noexcept -> tuple_element_t<I, pair<T1, T2>>&&
{
    if constexpr (I == 0) {
        return etl::move(p.first);
    } else {
        return etl::move(p.second);
    }
}

/// \brief Extracts an element from the pair using tuple-like interface.
///
/// \details The index-based overloads (1-4) fail to compile if the index I is
/// neither 0 nor 1. See Alisdar Meredith talk "Recreational C++" 35:00 to
/// 46:00. https://youtu.be/ovxNM865WaU
template <size_t I, typename T1, typename T2>
[[nodiscard]] constexpr auto get(pair<T1, T2> const&& p) noexcept -> tuple_element_t<I, pair<T1, T2>> const&&
{
    if constexpr (I == 0) {
        return etl::move(p.first);
    } else {
        return etl::move(p.second);
    }
}

template <
    typename T1,
    typename T2,
    typename U1,
    typename U2,
    template <typename>
    typename TQual,
    template <typename>
    typename UQual>
    requires requires {
        typename pair<common_reference_t<TQual<T1>, UQual<U1>>, common_reference_t<TQual<T2>, UQual<U2>>>;
    }
struct basic_common_reference<pair<T1, T2>, pair<U1, U2>, TQual, UQual> {
    using type = pair<common_reference_t<TQual<T1>, UQual<U1>>, common_reference_t<TQual<T2>, UQual<U2>>>;
};

} // namespace etl

#endif // TETL_UTILITY_PAIR_HPP
