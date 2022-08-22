/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_FUNCTIONAL_REFERENCE_WRAPPER_HPP
#define TETL_FUNCTIONAL_REFERENCE_WRAPPER_HPP

#include "etl/_memory/addressof.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/enable_if.hpp"
#include "etl/_type_traits/invoke_result.hpp"
#include "etl/_type_traits/is_same.hpp"
#include "etl/_type_traits/remove_cvref.hpp"
#include "etl/_utility/forward.hpp"

namespace etl {

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
    /// participates in overload resolution if `decay_t<U>` is not the same type
    /// as reference_wrapper and the expression `FUN(declval<U>())` is
    /// well-formed, where FUN names the set of imaginary functions:
    ///
    /// \code
    /// void FUN(T&) noexcept;
    /// void FUN(T&&) = delete;
    /// \endcode
    ///
    /// https://en.cppreference.com/w/cpp/utility/functional/reference_wrapper/reference_wrapper
    template <typename U, typename = decltype(detail::FUN<T>(declval<U>()),
                              enable_if_t<!is_same_v<reference_wrapper, remove_cvref_t<U>>>())>
    constexpr reference_wrapper(U&& u) noexcept(noexcept(detail::FUN<T>(forward<U>(u))))
        : ptr_(addressof(detail::FUN<T>(forward<U>(u))))
    {
    }

    /// \brief Constructs a new reference wrapper. Copy constructor. Stores a
    /// reference to other.get().
    constexpr reference_wrapper(reference_wrapper const& x) noexcept = default;

    /// \brief Copy assignment operator. Drops the current reference and stores
    /// a reference to other.get().
    constexpr auto operator=(reference_wrapper const& x) noexcept -> reference_wrapper& = default;

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
    constexpr auto operator()(Args&&... args) const noexcept(noexcept(invoke(get(), forward<Args>(args)...)))
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
[[nodiscard]] constexpr auto ref(reference_wrapper<T> t) noexcept -> reference_wrapper<T>
{
    return ref(t.get());
}

/// \brief Function templates ref and cref are helper functions that generate an
/// object of type reference_wrapper, using template argument deduction to
/// determine the template argument of the result.
/// module Utility
template <typename T>
[[nodiscard]] constexpr auto cref(T const& t) noexcept -> reference_wrapper<T const>
{
    return reference_wrapper<T const>(t);
}

template <typename T>
[[nodiscard]] constexpr auto cref(reference_wrapper<T> t) noexcept -> reference_wrapper<T const>
{
    return cref(t.get());
}

template <typename T>
void cref(T const&&) = delete;

} // namespace etl

#endif // TETL_FUNCTIONAL_REFERENCE_WRAPPER_HPP
