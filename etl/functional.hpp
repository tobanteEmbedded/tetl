/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_FUNCTIONAL_HPP
#define TAETL_FUNCTIONAL_HPP

#include "etl/byte.hpp"
#include "etl/definitions.hpp"
#include "etl/iterator.hpp"
#include "etl/new.hpp"
#include "etl/utility.hpp"

#include "etl/detail/algo_search.hpp"

namespace etl
{
/**
 * @brief Function object for performing addition. Effectively calls operator+ on two
 * instances of type T.
 *
 * * @ref https://en.cppreference.com/w/cpp/utility/functional/plus
 */
template <class T = void>
struct plus
{
    [[nodiscard]] constexpr auto operator()(const T& lhs, const T& rhs) const -> T
    {
        return lhs + rhs;
    }
};

/**
 * @brief Function object for performing addition. Effectively calls operator+ on two
 * instances of type T. The standard library provides a specialization of etl::plus when T
 * is not specified, which leaves the parameter types and return type to be deduced.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/plus_void
 */
template <>
struct plus<void>
{
    template <class T, class U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        -> decltype(etl::forward<T>(lhs) + etl::forward<U>(rhs))
    {
        return lhs + rhs;
    }

    // using is_transparent = true;
};

/**
 * @brief Function object for performing subtraction. Effectively calls operator- on two
 * instances of type T.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/minus
 */
template <class T = void>
struct minus
{
    [[nodiscard]] constexpr auto operator()(const T& lhs, const T& rhs) const -> T
    {
        return lhs - rhs;
    }
};

/**
 * @brief Function object for performing subtraction. Effectively calls operator- on two
 * instances of type T. The standard library provides a specialization of etl::minus when
 * T is not specified, which leaves the parameter types and return type to be deduced.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/minus_void
 */
template <>
struct minus<void>
{
    template <class T, class U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        -> decltype(etl::forward<T>(lhs) - etl::forward<U>(rhs))
    {
        return lhs - rhs;
    }

    // using is_transparent = true;
};

/**
 * @brief Function object for performing multiplication. Effectively calls operator* on
 * two instances of type T.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/multiplies
 */
template <class T = void>
struct multiplies
{
    [[nodiscard]] constexpr auto operator()(const T& lhs, const T& rhs) const -> T
    {
        return lhs * rhs;
    }
};

/**
 * @brief Function object for performing multiplication. Effectively calls operator* on
 * two instances of type T. The standard library provides a specialization of
 * etl::multiplies when T is not specified, which leaves the parameter types and return
 * type to be deduced.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/multiplies_void
 */
template <>
struct multiplies<void>
{
    template <class T, class U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        -> decltype(etl::forward<T>(lhs) * etl::forward<U>(rhs))
    {
        return lhs * rhs;
    }

    // using is_transparent = true;
};

/**
 * @brief Function object for performing division. Effectively calls operator/ on two
 * instances of type T.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/divides
 */
template <class T = void>
struct divides
{
    [[nodiscard]] constexpr auto operator()(const T& lhs, const T& rhs) const -> T
    {
        return lhs / rhs;
    }
};

/**
 * @brief Function object for performing division. Effectively calls operator/ on two
 * instances of type T. The standard library provides a specialization of etl::divides
 * when T is not specified, which leaves the parameter types and return type to be
 * deduced.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/divides_void
 */
template <>
struct divides<void>
{
    template <class T, class U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        -> decltype(etl::forward<T>(lhs) / etl::forward<U>(rhs))
    {
        return lhs / rhs;
    }

    // using is_transparent = true;
};

/**
 * @brief Function object for computing remainders of divisions. Implements operator% for
 * type T.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/modulus
 */
template <class T = void>
struct modulus
{
    [[nodiscard]] constexpr auto operator()(const T& lhs, const T& rhs) const -> T
    {
        return lhs % rhs;
    }
};

/**
 * @brief Function object for computing remainders of divisions. Implements operator% for
 * type T. The standard library provides a specialization of etl::modulus when T is not
 * specified, which leaves the parameter types and return type to be deduced.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/modulus_void
 */
template <>
struct modulus<void>
{
    template <class T, class U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        -> decltype(etl::forward<T>(lhs) % etl::forward<U>(rhs))
    {
        return lhs % rhs;
    }

    // using is_transparent = true;
};

/**
 * @brief Function object for performing negation. Effectively calls operator- on an
 * instance of type T.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/negate
 */
template <class T = void>
struct negate
{
    [[nodiscard]] constexpr auto operator()(const T& arg) const -> T { return -arg; }
};

/**
 * @brief Function object for performing negation. Effectively calls operator- on an
 * instance of type T. The standard library provides a specialization of etl::negate when
 * T is not specified, which leaves the parameter types and return type to be deduced.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/negate_void
 */
template <>
struct negate<void>
{
    template <class T>
    [[nodiscard]] constexpr auto operator()(T&& arg) const
        -> decltype(-etl::forward<T>(arg))
    {
        return -arg;
    }

    // using is_transparent = true;
};

/**
 * @brief Function object for performing comparisons. Unless specialised, invokes
 * operator== on type T.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/equal_to
 */
template <class T = void>
struct equal_to
{
    [[nodiscard]] constexpr auto operator()(const T& lhs, const T& rhs) const -> T
    {
        return lhs == rhs;
    }
};

/**
 * @brief Function object for performing comparisons. Unless specialised, invokes
 * operator== on type T. The standard library provides a specialization of etl::equal_to
 * when T is not specified, which leaves the parameter types and return type to be
 * deduced.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/equal_to_void
 */
template <>
struct equal_to<void>
{
    template <class T, class U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        -> decltype(etl::forward<T>(lhs) == etl::forward<U>(rhs))
    {
        return lhs == rhs;
    }

    // using is_transparent = true;
};

/**
 * @brief Function object for performing comparisons. Unless specialised, invokes
 * operator!= on type T.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/not_equal_to
 */
template <class T = void>
struct not_equal_to
{
    [[nodiscard]] constexpr auto operator()(const T& lhs, const T& rhs) const -> T
    {
        return lhs != rhs;
    }
};

/**
 * @brief Function object for performing comparisons. Unless specialised, invokes
 * operator!= on type T. The standard library provides a specialization of
 * etl::not_equal_to when T is not specified, which leaves the parameter types and return
 * type to be deduced.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/not_equal_to_void
 */
template <>
struct not_equal_to<void>
{
    template <class T, class U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        -> decltype(etl::forward<T>(lhs) != etl::forward<U>(rhs))
    {
        return lhs != rhs;
    }

    // using is_transparent = true;
};

/**
 * @brief Function object for performing comparisons. Unless specialised, invokes
 * operator> on type T.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/greater
 */
template <class T = void>
struct greater
{
    [[nodiscard]] constexpr auto operator()(const T& lhs, const T& rhs) const -> T
    {
        return lhs > rhs;
    }
};

/**
 * @brief Function object for performing comparisons. Unless specialised, invokes
 * operator> on type T. The standard library provides a specialization of
 * etl::greater when T is not specified, which leaves the parameter types and return
 * type to be deduced.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/greater_void
 */
template <>
struct greater<void>
{
    template <class T, class U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        -> decltype(etl::forward<T>(lhs) > etl::forward<U>(rhs))
    {
        return lhs > rhs;
    }

    // using is_transparent = true;
};

/**
 * @brief Function object for performing comparisons. Unless specialised, invokes
 * operator>= on type T.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/greater_equal
 */
template <class T = void>
struct greater_equal
{
    [[nodiscard]] constexpr auto operator()(const T& lhs, const T& rhs) const -> T
    {
        return lhs >= rhs;
    }
};

/**
 * @brief Function object for performing comparisons. Unless specialised, invokes
 * operator> on type T. The standard library provides a specialization of
 * etl::greater_equal when T is not specified, which leaves the parameter types and return
 * type to be deduced.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/greater_equal_void
 */
template <>
struct greater_equal<void>
{
    template <class T, class U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        -> decltype(etl::forward<T>(lhs) >= etl::forward<U>(rhs))
    {
        return lhs >= rhs;
    }

    // using is_transparent = true;
};

/**
 * @brief Function object for performing comparisons. Unless specialised, invokes
 * operator< on type T.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/less
 */
template <class T = void>
struct less
{
    [[nodiscard]] constexpr auto operator()(const T& lhs, const T& rhs) const -> bool
    {
        return lhs < rhs;
    }
};

/**
 * @brief Function object for performing comparisons. Unless specialised, invokes
 * operator< on type T. The standard library provides a specialization of etl::less
 * when T is not specified, which leaves the parameter types and return type to be
 * deduced.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/less_void
 */
template <>
struct less<void>
{
    template <class T, class U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        -> decltype(etl::forward<T>(lhs) < etl::forward<U>(rhs))
    {
        return lhs < rhs;
    }

    // using is_transparent = true;
};

/**
 * @brief Function object for performing comparisons. Unless specialised, invokes
 * operator<= on type T.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/less_equal
 */
template <class T = void>
struct less_equal
{
    [[nodiscard]] constexpr auto operator()(const T& lhs, const T& rhs) const -> bool
    {
        return lhs <= rhs;
    }
};

/**
 * @brief Function object for performing comparisons. Unless specialised, invokes
 * operator< on type T. The standard library provides a specialization of etl::less_equal
 * when T is not specified, which leaves the parameter types and return type to be
 * deduced.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/less_equal_void
 */
template <>
struct less_equal<void>
{
    template <class T, class U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        -> decltype(etl::forward<T>(lhs) <= etl::forward<U>(rhs))
    {
        return lhs <= rhs;
    }

    // using is_transparent = true;
};

/**
 * @brief Function object for performing logical AND (logical conjunction). Effectively
 * calls operator&& on type T.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/logical_and
 */
template <class T = void>
struct logical_and
{
    [[nodiscard]] constexpr auto operator()(const T& lhs, const T& rhs) const -> bool
    {
        return lhs && rhs;
    }
};

/**
 * @brief Function object for performing logical AND (logical conjunction). Effectively
 * calls operator&& on type T. The standard library provides a specialization of
 * etl::logical_and when T is not specified, which leaves the parameter types and return
 * type to be deduced.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/logical_and_void
 */
template <>
struct logical_and<void>
{
    template <class T, class U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        -> decltype(etl::forward<T>(lhs) && etl::forward<U>(rhs))
    {
        return lhs && rhs;
    }

    // using is_transparent = true;
};

/**
 * @brief Function object for performing logical OR (logical disjunction). Effectively
 * calls operator|| on type T.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/logical_or
 */
template <class T = void>
struct logical_or
{
    [[nodiscard]] constexpr auto operator()(const T& lhs, const T& rhs) const -> bool
    {
        return lhs || rhs;
    }
};

/**
 * @brief Function object for performing logical OR (logical disjunction). Effectively
 * calls operator|| on type T. The standard library provides a specialization of
 * etl::logical_or when T is not specified, which leaves the parameter types and return
 * type to be deduced.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/logical_or_void
 */
template <>
struct logical_or<void>
{
    template <class T, class U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        -> decltype(etl::forward<T>(lhs) || etl::forward<U>(rhs))
    {
        return lhs || rhs;
    }

    // using is_transparent = true;
};

/**
 * @brief Function object for performing logical NOT (logical negation). Effectively calls
 * operator! for type T.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/logical_not
 */
template <class T = void>
struct logical_not
{
    [[nodiscard]] constexpr auto operator()(const T& arg) const -> bool { return !arg; }
};

/**
 * @brief Function object for performing logical NOT (logical negation). Effectively calls
 * operator! for type T. The standard library provides a specialization of
 * etl::logical_not when T is not specified, which leaves the parameter types and return
 * type to be deduced.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/logical_not_void
 */
template <>
struct logical_not<void>
{
    template <class T>
    [[nodiscard]] constexpr auto operator()(T&& arg) const
        -> decltype(!etl::forward<T>(arg))
    {
        return !arg;
    }

    // using is_transparent = true;
};

/**
 * @brief Function object for performing bitwise AND. Effectively
 * calls operator& on type T.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/bit_and
 */
template <class T = void>
struct bit_and
{
    [[nodiscard]] constexpr auto operator()(const T& lhs, const T& rhs) const -> T
    {
        return lhs & rhs;
    }
};

/**
 * @brief Function object for performing bitwise AND. Effectively
 * calls operator& on type T. The standard library provides a specialization of
 * etl::bit_and when T is not specified, which leaves the parameter types and return
 * type to be deduced.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/bit_and_void
 */
template <>
struct bit_and<void>
{
    template <class T, class U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        -> decltype(etl::forward<T>(lhs) & etl::forward<U>(rhs))
    {
        return lhs & rhs;
    }

    // using is_transparent = true;
};

/**
 * @brief Function object for performing bitwise OR. Effectively calls operator| on type
 * T.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/bit_or
 */
template <class T = void>
struct bit_or
{
    [[nodiscard]] constexpr auto operator()(const T& lhs, const T& rhs) const -> T
    {
        return lhs | rhs;
    }
};

/**
 * @brief Function object for performing bitwise OR. Effectively calls operator| on type
 * T. The standard library provides a specialization of etl::bit_or when T is not
 * specified, which leaves the parameter types and return type to be deduced.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/bit_or_void
 */
template <>
struct bit_or<void>
{
    template <class T, class U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        -> decltype(etl::forward<T>(lhs) | etl::forward<U>(rhs))
    {
        return lhs | rhs;
    }

    // using is_transparent = true;
};

/**
 * @brief Function object for performing bitwise XOR. Effectively calls operator^ on type
 * T.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/bit_xor
 */
template <class T = void>
struct bit_xor
{
    [[nodiscard]] constexpr auto operator()(const T& lhs, const T& rhs) const -> T
    {
        return lhs ^ rhs;
    }
};

/**
 * @brief Function object for performing bitwise XOR. Effectively calls operator^ on type
 * T. The standard library provides a specialization of etl::bit_xor when T is not
 * specified, which leaves the parameter types and return type to be deduced.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/bit_xor_void
 */
template <>
struct bit_xor<void>
{
    template <class T, class U>
    [[nodiscard]] constexpr auto operator()(T&& lhs, U&& rhs) const
        -> decltype(etl::forward<T>(lhs) ^ etl::forward<U>(rhs))
    {
        return lhs ^ rhs;
    }

    // using is_transparent = true;
};

/**
 * @brief Function object for performing bitwise NOT.
 * Effectively calls operator~ on type T.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/bit_not
 */
template <class T = void>
struct bit_not
{
    [[nodiscard]] constexpr auto operator()(const T& arg) const -> T { return ~arg; }
};

/**
 * @brief Function object for performing bitwise NOT. Effectively calls operator~ on type
 * T. The standard library provides a specialization of etl::bit_not when T is not
 * specified, which leaves the parameter types and return type to be deduced.
 *
 * @ref https://en.cppreference.com/w/cpp/utility/functional/bit_not_void
 */
template <>
struct bit_not<void>
{
    template <class T>
    [[nodiscard]] constexpr auto operator()(T&& arg) const
        -> decltype(~etl::forward<T>(arg))
    {
        return ~arg;
    }

    // using is_transparent = true;
};

template <class>
class function_view;

template <class Result, class... Arguments>
class function_view<Result(Arguments...)>
{
public:
    using result_type = Result;

    function_view(function_view const& other)
    {
        if (&other == this) { return; }
        if (create_ptr_ != nullptr) { destroy_ptr_(storage_); }
        if (other.create_ptr_ != nullptr)
        {
            invoke_ptr_  = other.invoke_ptr_;
            create_ptr_  = other.create_ptr_;
            destroy_ptr_ = other.destroy_ptr_;
            create_ptr_(storage_, const_cast<etl::byte*>(other.storage_));
        }
    }

    auto operator=(function_view const& other) noexcept -> function_view&
    {
        if (&other == this) { return *this; }
        if (create_ptr_ != nullptr) { destroy_ptr_(storage_); }
        if (other.create_ptr_ != nullptr)
        {
            invoke_ptr_  = other.invoke_ptr_;
            create_ptr_  = other.create_ptr_;
            destroy_ptr_ = other.destroy_ptr_;
            create_ptr_(storage_, const_cast<etl::byte*>(other.storage_));
        }

        return *this;
    }

    ~function_view() noexcept { destroy_ptr_(storage_); }

    [[nodiscard]] auto operator()(Arguments&&... args) const -> result_type
    {
        return invoke_ptr_(const_cast<etl::byte*>(storage_),
                           etl::forward<Arguments>(args)...);  // NOLINT
    }

protected:
    template <typename Functor>
    function_view(Functor f, etl::byte* storage)
        : invoke_ptr_ {reinterpret_cast<invoke_pointer_t>(invoke<Functor>)}
        , create_ptr_ {reinterpret_cast<create_pointer_t>(create<Functor>)}
        , destroy_ptr_ {reinterpret_cast<destroy_pointer_t>(destroy<Functor>)}
        , storage_ {storage}
    {
        create_ptr_(storage_, &f);
    }

private:
    template <typename Functor>
    static auto invoke(Functor* f, Arguments&&... args) -> Result
    {
        return (*f)(etl::forward<Arguments>(args)...);
    }

    template <typename Functor>
    static auto create(Functor* destination, Functor* source) -> void
    {
        new (destination) Functor(*source);
    }

    template <typename Functor>
    static auto destroy(Functor* f) -> void
    {
        f->~Functor();
    }

    using invoke_pointer_t  = Result (*)(void*, Arguments&&...);
    using create_pointer_t  = void (*)(void*, void*);
    using destroy_pointer_t = void (*)(void*);

    invoke_pointer_t invoke_ptr_   = nullptr;
    create_pointer_t create_ptr_   = nullptr;
    destroy_pointer_t destroy_ptr_ = nullptr;

    etl::byte* storage_ = nullptr;
};

template <size_t, class>
class function;

template <size_t Capacity, class Result, class... Arguments>
class function<Capacity, Result(Arguments...)>
    : public function_view<Result(Arguments...)>
{
public:
    template <typename Functor>
    function(Functor f)
        : function_view<Result(Arguments...)> {
            etl::forward<Functor>(f),
            storage_,
        }
    {
        static_assert(sizeof(Functor) <= sizeof(storage_));
    }

private:
    etl::byte storage_[Capacity] {};
};

/**
 * @brief Default searcher. A class suitable for use with Searcher overload of etl::search
 * that delegates the search operation to the pre-C++17 standard library's etl::search.
 */
template <typename ForwardIter, typename Predicate = equal_to<>>
class default_searcher
{
public:
    default_searcher(ForwardIter f, ForwardIter l, Predicate p = Predicate())
        : first_(f), last_(l), predicate_(p)
    {
    }

    template <typename ForwardIter2>
    auto operator()(ForwardIter2 f, ForwardIter2 l) const
        -> etl::pair<ForwardIter2, ForwardIter2>
    {
        if (auto i = ::etl::detail::search_impl(f, l, first_, last_, predicate_); i != l)
        {
            auto j = ::etl::next(i, etl::distance(first_, last_));
            return etl::pair<ForwardIter2, ForwardIter2> {i, j};
        }

        return etl::pair<ForwardIter2, ForwardIter2> {l, l};
    }

private:
    ForwardIter first_;
    ForwardIter last_;
    Predicate predicate_;
};

}  // namespace etl

#endif  // TAETL_FUNCTIONAL_HPP