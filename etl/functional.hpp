// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_FUNCTIONAL_HPP
#define TETL_FUNCTIONAL_HPP

#include "etl/version.hpp"

#include "etl/_algorithm/search.hpp"
#include "etl/_functional/bit_and.hpp"
#include "etl/_functional/bit_not.hpp"
#include "etl/_functional/bit_or.hpp"
#include "etl/_functional/bit_xor.hpp"
#include "etl/_functional/divides.hpp"
#include "etl/_functional/equal_to.hpp"
#include "etl/_functional/greater.hpp"
#include "etl/_functional/greater_equal.hpp"
#include "etl/_functional/less.hpp"
#include "etl/_functional/less_equal.hpp"
#include "etl/_functional/logical_and.hpp"
#include "etl/_functional/logical_not.hpp"
#include "etl/_functional/logical_or.hpp"
#include "etl/_functional/minus.hpp"
#include "etl/_functional/modulus.hpp"
#include "etl/_functional/multiplies.hpp"
#include "etl/_functional/negate.hpp"
#include "etl/_functional/not_equal_to.hpp"
#include "etl/_functional/plus.hpp"

#include "etl/iterator.hpp"
#include "etl/new.hpp"

namespace etl {
namespace detail {
template <typename T, typename, typename = void>
struct is_transparent : ::etl::false_type {
};

/// \brief is_transparent
/// \group is_transparent
/// \module Utility
template <typename T, typename U>
struct is_transparent<T, U,
    ::etl::conditional_t<::etl::is_same_v<typename T::is_transparent, void>,
        void, bool>> : ::etl::true_type {
};

/// \group is_transparent
template <typename T, typename U>
inline constexpr auto transparent_v = is_transparent<T, U>::value;

} // namespace detail

namespace detail {
template <typename T>
constexpr auto FUN(T& t) noexcept -> T&
{
    return t;
}

template <typename T>
void FUN(T&&) = delete;

} // namespace detail

/// \brief reference_wrapper is a class template that wraps a reference in a
/// copyable, assignable object. It is frequently used as a mechanism to store
/// references inside standard containers (like etl::static_vector) which cannot
/// normally hold references. Specifically, reference_wrapper is a
/// CopyConstructible and CopyAssignable wrapper around a reference to object or
/// reference to function of type T. Instances of reference_wrapper are objects
/// (they can be copied or stored in containers) but they are implicitly
/// convertible to T&, so that they can be used as arguments with the functions
/// that take the underlying type by reference. If the stored reference is
/// Callable, reference_wrapper is callable with the same arguments.
template <typename T>
struct reference_wrapper {
    using type = T;

    /// \brief Constructs a new reference wrapper. Converts x to T& as if by T&
    /// t = forward<U>(x);, then stores a reference to t. This overload only
    /// participates in overload resolution if decay_t<U> is not the same type
    /// as reference_wrapper and the expression FUN(declval<U>()) is
    /// well-formed, where FUN names the set of imaginary functions:
    ///
    /// void FUN(T&) noexcept;
    /// void FUN(T&&) = delete;
    ///
    /// \notes
    /// [cppreference.com/w/cpp/utility/functional/reference_wrapper/reference_wrapper](https://en.cppreference.com/w/cpp/utility/functional/reference_wrapper/reference_wrapper)
    template <typename U,
        typename = decltype(detail::FUN<T>(declval<U>()),
            enable_if_t<!is_same_v<reference_wrapper, remove_cvref_t<U>>>())>
    constexpr reference_wrapper(U&& u) noexcept(
        noexcept(detail::FUN<T>(forward<U>(u))))
        : ptr_(addressof(detail::FUN<T>(forward<U>(u))))
    {
    }

    /// \brief Constructs a new reference wrapper. Copy constructor. Stores a
    /// reference to other.get().
    constexpr reference_wrapper(reference_wrapper const& x) noexcept = default;

    /// \brief Copy assignment operator. Drops the current reference and stores
    /// a reference to other.get().
    constexpr auto operator   =(reference_wrapper const& x) noexcept
        -> reference_wrapper& = default;

    /// \brief Returns the stored reference.
    [[nodiscard]] constexpr operator type&() const noexcept { return *ptr_; }

    /// \brief Returns the stored reference.
    [[nodiscard]] constexpr auto get() const noexcept -> type& { return *ptr_; }

    /// \brief Calls the Callable object, reference to which is stored. This
    /// function is available only if the stored reference points to a Callable
    /// object. T must be a complete type.
    ///
    /// \returns The return value of the called function.
    template <typename... Args>
    constexpr auto operator()(Args&&... args) const
        noexcept(noexcept(invoke(get(), forward<Args>(args)...)))
            -> invoke_result_t<T&, Args...>
    {
        return invoke(get(), forward<Args>(args)...);
    }

private:
    type* ptr_;
};

// One deduction guide is provided for reference_wrapper to support
// deduction of the sole class template parameter.
template <typename T>
reference_wrapper(T&) -> reference_wrapper<T>;

/// \brief Function templates ref and cref are helper functions that generate an
/// object of type reference_wrapper, using template argument deduction to
/// determine the template argument of the result.
template <typename T>
[[nodiscard]] constexpr auto ref(T& t) noexcept -> reference_wrapper<T>
{
    return reference_wrapper<T>(t);
}

/// \brief Function templates ref and cref are helper functions that generate an
/// object of type reference_wrapper, using template argument deduction to
/// determine the template argument of the result.
template <typename T>
[[nodiscard]] constexpr auto ref(reference_wrapper<T> t) noexcept
    -> reference_wrapper<T>
{
    return ref(t.get());
}

/// \brief Function templates ref and cref are helper functions that generate an
/// object of type reference_wrapper, using template argument deduction to
/// determine the template argument of the result.
/// \group cref
/// module Utility
template <typename T>
[[nodiscard]] constexpr auto cref(T const& t) noexcept
    -> reference_wrapper<T const>
{
    return reference_wrapper<T const>(t);
}

/// \group cref
template <typename T>
[[nodiscard]] constexpr auto cref(reference_wrapper<T> t) noexcept
    -> reference_wrapper<T const>
{
    return cref(t.get());
}

/// \group cref
template <typename T>
void cref(T const&&) = delete;

/// \brief Default searcher. A class suitable for use with Searcher overload of
/// etl::search that delegates the search operation to the pre-C++17 standard
/// library's etl::search.
/// \module Utility
template <typename ForwardIter, typename Predicate = equal_to<>>
struct default_searcher {
    default_searcher(ForwardIter f, ForwardIter l, Predicate p = Predicate())
        : first_(f), last_(l), predicate_(p)
    {
    }

    template <typename ForwardIter2>
    auto operator()(ForwardIter2 f, ForwardIter2 l) const
        -> etl::pair<ForwardIter2, ForwardIter2>
    {
        if (auto i
            = ::etl::detail::search_impl(f, l, first_, last_, predicate_);
            i != l) {
            auto j = ::etl::next(i, etl::distance(first_, last_));
            return etl::pair<ForwardIter2, ForwardIter2> { i, j };
        }

        return etl::pair<ForwardIter2, ForwardIter2> { l, l };
    }

private:
    ForwardIter first_;
    ForwardIter last_;
    Predicate predicate_;
};

/// \brief hash
/// \group hash
/// \module Utility
template <typename T>
struct hash;

/// \group hash
/// \module Utility
template <>
struct hash<bool> {
    [[nodiscard]] constexpr auto operator()(bool val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<char> {
    [[nodiscard]] constexpr auto operator()(char val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<signed char> {
    [[nodiscard]] constexpr auto operator()(signed char val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<unsigned char> {
    [[nodiscard]] constexpr auto operator()(unsigned char val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<char16_t> {
    [[nodiscard]] constexpr auto operator()(char16_t val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<char32_t> {
    [[nodiscard]] constexpr auto operator()(char32_t val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<wchar_t> {
    [[nodiscard]] constexpr auto operator()(wchar_t val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<short> {
    [[nodiscard]] constexpr auto operator()(short val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<unsigned short> {
    [[nodiscard]] constexpr auto operator()(unsigned short val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<int> {
    [[nodiscard]] constexpr auto operator()(int val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<unsigned int> {
    [[nodiscard]] constexpr auto operator()(unsigned int val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<long> {
    [[nodiscard]] constexpr auto operator()(long val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<long long> {
    [[nodiscard]] constexpr auto operator()(long long val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<unsigned long> {
    [[nodiscard]] constexpr auto operator()(unsigned long val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<unsigned long long> {
    [[nodiscard]] constexpr auto operator()(
        unsigned long long val) const noexcept -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<float> {
    [[nodiscard]] constexpr auto operator()(float val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<double> {
    [[nodiscard]] constexpr auto operator()(double val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};
/// \group hash
/// \module Utility
template <>
struct hash<long double> {
    [[nodiscard]] constexpr auto operator()(long double val) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(val);
    }
};

/// \group hash
/// \module Utility
template <>
struct hash<etl::nullptr_t> {
    [[nodiscard]] auto operator()(nullptr_t /*unused*/) const noexcept
        -> etl::size_t
    {
        return static_cast<etl::size_t>(0);
    }
};

/// \group hash
/// \module Utility
template <typename T>
struct hash<T*> {
    [[nodiscard]] auto operator()(T* val) const noexcept -> etl::size_t
    {
        return reinterpret_cast<etl::size_t>(val);
    }
};

} // namespace etl

#endif // TETL_FUNCTIONAL_HPP