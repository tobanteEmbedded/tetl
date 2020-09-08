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

#ifndef TAETL_ITERATOR_HPP
#define TAETL_ITERATOR_HPP

#include "etl/definitions.hpp"
#include "etl/memory.hpp"
#include "etl/type_traits.hpp"
#include "etl/utility.hpp"
#include "etl/warning.hpp"

namespace etl
{
/**
 * @brief Returns an iterator to the beginning of the given container c or array
 * array. These templates rely on C::begin() having a reasonable implementation.
 * Returns exactly c.begin(), which is typically an iterator to the beginning of
 * the sequence represented by c. If C is a standard Container, this returns
 * C::iterator when c is not const-qualified, and C::const_iterator otherwise.
 *
 * @details Custom overloads of begin may be provided for classes that do not
 * expose a suitable begin() member function, yet can be iterated.
 */
template <class C>
constexpr auto begin(C& c) -> decltype(c.begin())
{
    return c.begin();
}

/**
 * @brief Returns an iterator to the beginning of the given container c or array
 * array. These templates rely on C::begin() having a reasonable implementation.
 * Returns exactly c.begin(), which is typically an iterator to the beginning of
 * the sequence represented by c. If C is a standard Container, this returns
 * C::iterator when c is not const-qualified, and C::const_iterator otherwise.
 *
 * @details Custom overloads of begin may be provided for classes that do not
 * expose a suitable begin() member function, yet can be iterated.
 */
template <class C>
constexpr auto begin(const C& c) -> decltype(c.begin())
{
    return c.begin();
}

/**
 * @brief Returns an iterator to the beginning of the given container c or array
 * array. These templates rely on C::begin() having a reasonable implementation.
 * Returns a pointer to the beginning of the array.
 *
 * @details Custom overloads of begin may be provided for classes that do not
 * expose a suitable begin() member function, yet can be iterated.
 */
template <class T, etl::size_t N>
constexpr auto begin(T (&array)[N]) noexcept -> T*
{
    return &array[0];
}

/**
 * @brief Returns an iterator to the beginning of the given container c or
 * array array. These templates rely on C::begin() having a reasonable
 * implementation. Returns exactly etl::begin(c), with c always treated as
 * const-qualified. If C is a standard Container, this always returns
 * C::const_iterator.
 *
 * @details Custom overloads of begin may be provided for classes that do
 * not expose a suitable begin() member function, yet can be iterated.
 */
template <class C>
constexpr auto cbegin(const C& c) noexcept(noexcept(etl::begin(c)))
    -> decltype(etl::begin(c))
{
    return etl::begin(c);
}

/**
 * @brief Returns an iterator to the end (i.e. the element after the last
 * element) of the given container c or array array. These templates rely on
 * C::end() having a reasonable implementation.
 */
template <class C>
constexpr auto end(C& c) -> decltype(c.end())
{
    return c.end();
}

/**
 * @brief Returns an iterator to the end (i.e. the element after the last
 * element) of the given container c or array array. These templates rely on
 * C::end() having a reasonable implementation.
 */
template <class C>
constexpr auto end(const C& c) -> decltype(c.end())
{
    return c.end();
}

/**
 * @brief Returns an iterator to the end (i.e. the element after the last
 * element) of the given container c or array array. These templates rely on
 * C::end() having a reasonable implementation.
 */
template <class T, etl::size_t N>
constexpr auto end(T (&array)[N]) noexcept -> T*
{
    return &array[N];
}

/**
 * @brief Returns an iterator to the end (i.e. the element after the last
 * element) of the given container c or array array. These templates rely on
 * C::end() having a reasonable implementation.
 */
template <class C>
constexpr auto cend(const C& c) noexcept(noexcept(etl::end(c))) -> decltype(etl::end(c))
{
    return etl::end(c);
}

/**
 * @brief Returns the size of the given container c or array array. Returns
 * c.size(), converted to the return type if necessary.
 */
template <typename C>
constexpr auto size(C const& c) noexcept(noexcept(c.size())) -> decltype(c.size())
{
    return c.size();
}

/**
 * @brief Returns the size of the given container c or array array. Returns N.
 */
template <class T, etl::size_t N>
constexpr auto size(const T (&array)[N]) noexcept -> etl::size_t
{
    etl::ignore_unused(&array[0]);
    return N;
}

/**
 * @brief Returns whether the given container is empty.
 */
template <typename C>
constexpr auto empty(const C& c) noexcept(noexcept(c.empty())) -> decltype(c.empty())
{
    return c.empty();
}

/**
 * @brief Returns whether the given container is empty.
 */
template <typename T, etl::size_t N>
constexpr auto empty(T (&array)[N]) noexcept -> bool
{
    etl::ignore_unused(&array);
    return false;
}

/**
 * @brief Returns a pointer to the block of memory containing the elements of
 * the container. Returns c.data().
 */
template <typename C>
constexpr auto data(C& c) noexcept(noexcept(c.data())) -> decltype(c.data())
{
    return c.data();
}

/**
 * @brief Returns a pointer to the block of memory containing the elements of
 * the container. Returns c.data().
 */
template <typename C>
constexpr auto data(const C& c) noexcept(noexcept(c.data())) -> decltype(c.data())
{
    return c.data();
}

/**
 * @brief Returns a pointer to the block of memory containing the elements of
 * the container. Returns &array[0].
 */
template <typename T, etl::size_t N>
constexpr auto data(T (&array)[N]) noexcept -> T*
{
    return &array[0];
}

/**
 * @brief Defines the category of an iterator. Each tag is an empty type and
 * corresponds to one of the five (until C++20) six (since C++20) iterator
 * categories.
 */
struct input_iterator_tag
{
};

/**
 * @brief Defines the category of an iterator. Each tag is an empty type and
 * corresponds to one of the five (until C++20) six (since C++20) iterator
 * categories.
 */
struct output_iterator_tag
{
};

/**
 * @brief Defines the category of an iterator. Each tag is an empty type and
 * corresponds to one of the five (until C++20) six (since C++20) iterator
 * categories.
 */
struct forward_iterator_tag : public input_iterator_tag
{
};

/**
 * @brief Defines the category of an iterator. Each tag is an empty type and
 * corresponds to one of the five (until C++20) six (since C++20) iterator
 * categories.
 */
struct bidirectional_iterator_tag : public forward_iterator_tag
{
};

/**
 * @brief Defines the category of an iterator. Each tag is an empty type and
 * corresponds to one of the five (until C++20) six (since C++20) iterator
 * categories.
 */
struct random_access_iterator_tag : public bidirectional_iterator_tag
{
};

/**
 * @brief Defines the category of an iterator. Each tag is an empty type and
 * corresponds to one of the five (until C++20) six (since C++20) iterator
 * categories.
 */
struct contiguous_iterator_tag : public random_access_iterator_tag
{
};

/**
 * @brief etl::iterator_traits is the type trait class that provides uniform
 * interface to the properties of LegacyIterator types. This makes it possible
 * to implement algorithms only in terms of iterators.
 *
 * @details The template can be specialized for user-defined iterators so that
 * the information about the iterator can be retrieved even if the type does not
 * provide the usual typedefs.
 *
 * @ref https://en.cppreference.com/w/cpp/iterator/iterator_traits
 */
template <class Iter>
struct iterator_traits;

/**
 * @brief etl::iterator_traits is the type trait class that provides uniform
 * interface to the properties of LegacyIterator types. This makes it possible
 * to implement algorithms only in terms of iterators.
 *
 * @details The template can be specialized for user-defined iterators so that
 * the information about the iterator can be retrieved even if the type does not
 * provide the usual typedefs.
 *
 * @ref https://en.cppreference.com/w/cpp/iterator/iterator_traits
 */
template <class T>
struct iterator_traits<T*>
{
    using iterator_concept  = contiguous_iterator_tag;
    using iterator_category = random_access_iterator_tag;
    using value_type        = remove_cv_t<T>;
    using difference_type   = ptrdiff_t;
    using pointer           = T*;
    using reference         = T&;
};

/**
 * @brief Increments given iterator it by n elements. If n is negative, the
 * iterator is decremented. In this case, InputIt must meet the requirements of
 * LegacyBidirectionalIterator, otherwise the behavior is undefined.
 *
 * @ref https://en.cppreference.com/w/cpp/iterator/advance
 */
template <class It, class Distance>
constexpr auto advance(It& it, Distance n) -> void
{
    using category = typename etl::iterator_traits<It>::iterator_category;
    static_assert(etl::is_base_of_v<etl::input_iterator_tag, category>);

    auto dist = typename etl::iterator_traits<It>::difference_type(n);
    if constexpr (etl::is_base_of_v<etl::random_access_iterator_tag, category>)
    { it += dist; }
    else
    {
        while (dist > 0)
        {
            --dist;
            ++it;
        }
        if constexpr (etl::is_base_of_v<etl::bidirectional_iterator_tag, category>)
        {
            while (dist < 0)
            {
                ++dist;
                --it;
            }
        }
    }
}

/**
 * @brief Returns the number of hops from first to last.
 *
 * @ref https://en.cppreference.com/w/cpp/iterator/distance
 */
template <class It>
constexpr auto distance(It first, It last) ->
    typename etl::iterator_traits<It>::difference_type
{
    using category = typename etl::iterator_traits<It>::iterator_category;
    static_assert(etl::is_base_of_v<etl::input_iterator_tag, category>);

    if constexpr (etl::is_base_of_v<etl::random_access_iterator_tag, category>)
    { return last - first; }
    else
    {
        typename etl::iterator_traits<It>::difference_type result = 0;
        while (first != last)
        {
            ++first;
            ++result;
        }
        return result;
    }
}

/**
 * @brief Return the nth successor of iterator it.
 */
template <class InputIt>
[[nodiscard]] constexpr auto
next(InputIt it, typename etl::iterator_traits<InputIt>::difference_type n = 1) -> InputIt
{
    etl::advance(it, n);
    return it;
}

/**
 * @brief Return the nth predecessor of iterator it.
 */
template <class BidirIt>
[[nodiscard]] constexpr auto
prev(BidirIt it, typename etl::iterator_traits<BidirIt>::difference_type n = 1) -> BidirIt
{
    etl::advance(it, -n);
    return it;
}

/**
 * @brief etl::back_insert_iterator is a LegacyOutputIterator that appends to a
 * container for which it was constructed. The container's push_back() member
 * function is called whenever the iterator (whether dereferenced or not) is
 * assigned to. Incrementing the etl::back_insert_iterator is a no-op.
 */
template <class Container>
class back_insert_iterator
{
protected:
    Container* container_ = nullptr;

public:
    using iterator_category = output_iterator_tag;
    using value_type        = void;
    using difference_type   = ptrdiff_t;
    using pointer           = void;
    using reference         = void;
    using container_type    = Container;

    /**
     * @brief Initializes the underlying pointer to container with nullptr.
     */
    constexpr back_insert_iterator() noexcept = default;

    /**
     * @brief Initializes the underlying pointer to the container to
     * etl::addressof(c).
     */
    constexpr explicit back_insert_iterator(Container& container)
        : container_ {etl::addressof(container)}
    {
    }

    /**
     * @brief Inserts the given value value to the container.
     */
    constexpr auto operator=(const typename Container::value_type& value)
        -> back_insert_iterator&
    {
        container_->push_back(value);
        return *this;
    }

    /**
     * @brief Inserts the given value value to the container.
     */
    constexpr auto operator=(typename Container::value_type&& value)
        -> back_insert_iterator&
    {
        container_->push_back(etl::move(value));
        return *this;
    }

    /**
     * @brief Does nothing, this member function is provided to satisfy the
     * requirements of LegacyOutputIterator. It returns the iterator itself,
     * which makes it possible to use code such as *iter = value to output
     * (insert) the value into the underlying container.
     */
    constexpr auto operator*() -> back_insert_iterator& { return *this; }

    /**
     * @brief Does nothing. These operator overloads are provided to satisfy the
     * requirements of LegacyOutputIterator. They make it possible for the
     * expressions *iter++=value and *++iter=value to be used to output (insert)
     * a value into the underlying container.
     */
    constexpr auto operator++() -> back_insert_iterator& { return *this; }

    /**
     * @brief Does nothing. These operator overloads are provided to satisfy the
     * requirements of LegacyOutputIterator. They make it possible for the
     * expressions *iter++=value and *++iter=value to be used to output (insert)
     * a value into the underlying container.
     */
    constexpr auto operator++(int) -> back_insert_iterator { return *this; }
};

/**
 * back_inserter is a convenience function template that constructs a
 * etl::back_insert_iterator for the container c with the type deduced from the
 * type of the argument.
 */
template <class Container>
[[nodiscard]] constexpr auto back_inserter(Container& container)
    -> back_insert_iterator<Container>
{
    return etl::back_insert_iterator<Container>(container);
}

/**
 * @brief etl::front_insert_iterator is an LegacyOutputIterator that prepends
 * elements to a container for which it was constructed. The container's
 * push_front() member function is called whenever the iterator (whether
 * dereferenced or not) is assigned to. Incrementing the
 * etl::front_insert_iterator is a no-op.
 *
 * @todo Add tests when a container with push_front has been implemented.
 */
template <class Container>
class front_insert_iterator
{
protected:
    Container* container_ = nullptr;

public:
    using iterator_category = output_iterator_tag;
    using value_type        = void;
    using difference_type   = void;
    using pointer           = void;
    using reference         = void;
    using container_type    = Container;

    /**
     * @brief Initializes the underlying pointer to container with nullptr.
     */
    constexpr front_insert_iterator() noexcept = default;

    /**
     * @brief Initializes the underlying pointer to the container to
     * etl::addressof(c).
     */
    constexpr explicit front_insert_iterator(Container& container)
        : container_ {etl::addressof(container)}
    {
    }

    /**
     * @brief Inserts the given value value to the container.
     */
    constexpr auto operator=(const typename Container::value_type& value)
        -> front_insert_iterator&
    {
        container_->push_front(value);
        return *this;
    }

    /**
     * @brief Inserts the given value value to the container.
     */
    constexpr auto operator=(typename Container::value_type&& value)
        -> front_insert_iterator&
    {
        container_->push_front(etl::move(value));
        return *this;
    }

    /**
     * @brief Does nothing, this member function is provided to satisfy the
     * requirements of LegacyOutputIterator. It returns the iterator itself,
     * which makes it possible to use code such as *iter = value to output
     * (insert) the value into the underlying container.
     */
    constexpr auto operator*() -> front_insert_iterator& { return *this; }

    /**
     * @brief Does nothing. These operator overloads are provided to satisfy the
     * requirements of LegacyOutputIterator. They make it possible for the
     * expressions *iter++=value and *++iter=value to be used to output (insert)
     * a value into the underlying container.
     */
    constexpr auto operator++() -> front_insert_iterator& { return *this; }

    /**
     * @brief Does nothing. These operator overloads are provided to satisfy the
     * requirements of LegacyOutputIterator. They make it possible for the
     * expressions *iter++=value and *++iter=value to be used to output (insert)
     * a value into the underlying container.
     */
    constexpr auto operator++(int) -> front_insert_iterator { return *this; }
};

/**
 * @brief front_inserter is a convenience function template that constructs a
 * etl::front_insert_iterator for the container c with the type deduced from the
 * type of the argument.
 */
template <class Container>
[[nodiscard]] constexpr auto front_inserter(Container& c)
    -> etl::front_insert_iterator<Container>
{
    return etl::front_insert_iterator<Container>(c);
}

}  // namespace etl

#endif  // TAETL_ITERATOR_HPP
