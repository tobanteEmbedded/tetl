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

#ifndef TETL_ITERATOR_HPP
#define TETL_ITERATOR_HPP

#include "etl/version.hpp"

#include "etl/cstddef.hpp"
#include "etl/memory.hpp"
#include "etl/type_traits.hpp"
#include "etl/utility.hpp"

#include "etl/_config/warning.hpp"
#include "etl/_iterator/advance.hpp"
#include "etl/_iterator/begin.hpp"
#include "etl/_iterator/data.hpp"
#include "etl/_iterator/distance.hpp"
#include "etl/_iterator/empty.hpp"
#include "etl/_iterator/end.hpp"
#include "etl/_iterator/iterator_traits.hpp"
#include "etl/_iterator/next.hpp"
#include "etl/_iterator/prev.hpp"
#include "etl/_iterator/rbegin.hpp"
#include "etl/_iterator/rend.hpp"
#include "etl/_iterator/size.hpp"
#include "etl/_iterator/tags.hpp"

namespace etl {

/// \brief reverse_iterator is an iterator adaptor that reverses the direction
/// of a given iterator. In other words, when provided with a bidirectional
/// iterator, `reverse_iterator` produces a new iterator that moves from the end
/// to the beginning of the sequence defined by the underlying bidirectional
/// iterator. This is the iterator returned by member functions `rbegin()` and
/// `rend()` of the standard library containers. \notes
/// [cppreference.com/w/cpp/iterator/reverse_iterator](https://en.cppreference.com/w/cpp/iterator/reverse_iterator)
/// \module Iterator
template <typename Iter>
struct reverse_iterator {
    /// The underlying iterator type
    using iterator_type = Iter;
    /// The underlying value type
    using value_type = typename iterator_traits<Iter>::value_type;
    /// The type of subtracting to iterators
    using difference_type =
        typename etl::iterator_traits<Iter>::difference_type;
    /// The underlying reference type
    using reference = typename etl::iterator_traits<Iter>::reference;
    /// The underlying pointer type
    using pointer = typename etl::iterator_traits<Iter>::pointer;

    /// \brief Constructs a new iterator adaptor.
    ///
    /// \details Default constructor. The underlying iterator is
    /// value-initialized. Operations on the resulting iterator have defined
    /// behavior if and only if the corresponding operations on a
    /// value-initialized Iterator also have defined behavior.
    constexpr reverse_iterator() : current_() { }

    /// \brief Constructs a new iterator adaptor.
    ///
    /// \details The underlying iterator is initialized with x.
    constexpr explicit reverse_iterator(Iter x) : current_(x) { }

    /// \brief Constructs a new iterator adaptor.
    ///
    /// \details The underlying iterator is initialized with that of other.
    template <typename Other>
    constexpr reverse_iterator(reverse_iterator<Other> const& other)
        : current_(other.base())
    {
    }

    /// \brief The underlying iterator is assigned the value of the underlying
    /// iterator of other, i.e. other.base().
    template <typename Other>
    constexpr auto operator=(reverse_iterator<Other> const& other)
        -> reverse_iterator&
    {
        current_ = other.base();
        return *this;
    }

    /// \brief Returns the underlying base iterator.
    [[nodiscard]] constexpr auto base() const -> Iter { return current_; }

    /// \brief Returns a reference to the element previous to current.
    constexpr auto operator*() const -> reference
    {
        auto tmp = current_;
        return *--tmp;
    }

    /// \brief Returns a pointer to the element previous to current.
    constexpr auto operator->() const -> pointer
    {
        return etl::addressof(operator*());
    }

    /// \brief Pre-increments by one respectively.
    constexpr auto operator++() -> reverse_iterator&
    {
        --current_;
        return *this;
    }

    /// \brief Pre-increments by one respectively.
    constexpr auto operator++(int) -> reverse_iterator
    {
        auto tmp(*this);
        --current_;
        return tmp;
    }

    /// \brief Pre-decrements by one respectively.
    constexpr auto operator--() -> reverse_iterator&
    {
        ++current_;
        return *this;
    }

    /// \brief Pre-decrements by one respectively.
    constexpr auto operator--(int) -> reverse_iterator
    {
        auto tmp(*this);
        ++current_;
        return tmp;
    }

    /// \brief Returns an iterator which is advanced by n positions.
    constexpr auto operator+(difference_type n) const -> reverse_iterator
    {
        return reverse_iterator(current_ - n);
    }

    /// \brief Advances the iterator by n or -n positions respectively.
    constexpr auto operator+=(difference_type n) -> reverse_iterator&
    {
        current_ -= n;
        return *this;
    }

    /// \brief Returns an iterator which is advanced by -n positions.
    constexpr auto operator-(difference_type n) const -> reverse_iterator
    {
        return reverse_iterator(current_ + n);
    }

    /// \brief Advances the iterator by n or -n positions respectively.
    constexpr auto operator-=(difference_type n) -> reverse_iterator&
    {
        current_ += n;
        return *this;
    }

    /// \brief Returns a reference to the element at specified relative
    /// location.
    constexpr auto operator[](difference_type n) const -> reference
    {
        return *(*this + n);
    }

private:
    Iter current_;
};

/// \brief Convenience function template that constructs a etl::reverse_iterator
/// for the given iterator i (which must be a LegacyBidirectionalIterator) with
/// the type deduced from the type of the argument.
template <typename Iter>
[[nodiscard]] constexpr auto make_reverse_iterator(Iter i) noexcept
    -> etl::reverse_iterator<Iter>
{
    return etl::reverse_iterator<Iter>(i);
}

/// \brief Compares the underlying iterators. Inverse comparisons are applied in
/// order to take into account that the iterator order is reversed.
template <typename Iter1, typename Iter2>
[[nodiscard]] constexpr auto operator==(etl::reverse_iterator<Iter1> const& lhs,
    etl::reverse_iterator<Iter2> const& rhs) -> bool
{
    return lhs.base() == rhs.base();
}

/// \brief Compares the underlying iterators. Inverse comparisons are applied in
/// order to take into account that the iterator order is reversed.
template <typename Iter1, typename Iter2>
[[nodiscard]] constexpr auto operator!=(etl::reverse_iterator<Iter1> const& lhs,
    etl::reverse_iterator<Iter2> const& rhs) -> bool
{
    return lhs.base() != rhs.base();
}

/// \brief Compares the underlying iterators. Inverse comparisons are applied in
/// order to take into account that the iterator order is reversed.
template <typename Iter1, typename Iter2>
[[nodiscard]] constexpr auto operator<(etl::reverse_iterator<Iter1> const& lhs,
    etl::reverse_iterator<Iter2> const& rhs) -> bool
{
    return lhs.base() < rhs.base();
}

/// \brief Compares the underlying iterators. Inverse comparisons are applied in
/// order to take into account that the iterator order is reversed.
template <typename Iter1, typename Iter2>
[[nodiscard]] constexpr auto operator<=(etl::reverse_iterator<Iter1> const& lhs,
    etl::reverse_iterator<Iter2> const& rhs) -> bool
{
    return lhs.base() <= rhs.base();
}

/// \brief Compares the underlying iterators. Inverse comparisons are applied in
/// order to take into account that the iterator order is reversed.
template <typename Iter1, typename Iter2>
[[nodiscard]] constexpr auto operator>(etl::reverse_iterator<Iter1> const& lhs,
    etl::reverse_iterator<Iter2> const& rhs) -> bool
{
    return lhs.base() > rhs.base();
}

/// \brief Compares the underlying iterators. Inverse comparisons are applied in
/// order to take into account that the iterator order is reversed.
template <typename Iter1, typename Iter2>
[[nodiscard]] constexpr auto operator>=(etl::reverse_iterator<Iter1> const& lhs,
    etl::reverse_iterator<Iter2> const& rhs) -> bool
{
    return lhs.base() >= rhs.base();
}

/// \brief etl::back_insert_iterator is a LegacyOutputIterator that appends to a
/// container for which it was constructed. The container's push_back() member
/// function is called whenever the iterator (whether dereferenced or not) is
/// assigned to. Incrementing the etl::back_insert_iterator is a no-op.
/// \module Iterator
template <typename Container>
struct back_insert_iterator {
    using iterator_category = output_iterator_tag;
    using value_type        = void;
    using difference_type   = ptrdiff_t;
    using pointer           = void;
    using reference         = void;
    using container_type    = Container;

    /// \brief Initializes the underlying pointer to container with nullptr.
    constexpr back_insert_iterator() noexcept = default;

    /// \brief Initializes the underlying pointer to the container to
    /// etl::addressof(c).
    constexpr explicit back_insert_iterator(Container& container)
        : container_ { etl::addressof(container) }
    {
    }

    /// \brief Inserts the given value value to the container.
    constexpr auto operator=(typename Container::value_type const& value)
        -> back_insert_iterator&
    {
        container_->push_back(value);
        return *this;
    }

    /// \brief Inserts the given value value to the container.
    constexpr auto operator=(typename Container::value_type&& value)
        -> back_insert_iterator&
    {
        container_->push_back(etl::move(value));
        return *this;
    }

    /// \brief Does nothing, this member function is provided to satisfy the
    /// requirements of LegacyOutputIterator. It returns the iterator itself,
    /// which makes it possible to use code such as *iter = value to output
    /// (insert) the value into the underlying container.
    constexpr auto operator*() -> back_insert_iterator& { return *this; }

    /// \brief Does nothing. These operator overloads are provided to satisfy
    /// the requirements of LegacyOutputIterator. They make it possible for the
    /// expressions *iter++=value and *++iter=value to be used to output
    /// (insert) a value into the underlying container.
    constexpr auto operator++() -> back_insert_iterator& { return *this; }

    /// \brief Does nothing. These operator overloads are provided to satisfy
    /// the requirements of LegacyOutputIterator. They make it possible for the
    /// expressions *iter++=value and *++iter=value to be used to output
    /// (insert) a value into the underlying container.
    constexpr auto operator++(int) -> back_insert_iterator { return *this; }

private:
    Container* container_ = nullptr;
};

/// back_inserter is a convenience function template that constructs a
/// back_insert_iterator for the container c with the type deduced from the
/// type of the argument.
/// \module Iterator
template <typename Container>
[[nodiscard]] constexpr auto back_inserter(Container& container)
    -> back_insert_iterator<Container>
{
    return back_insert_iterator<Container>(container);
}

/// \brief front_insert_iterator is an LegacyOutputIterator that prepends
/// elements to a container for which it was constructed. The container's
/// push_front() member function is called whenever the iterator (whether
/// dereferenced or not) is assigned to. Incrementing the
/// front_insert_iterator is a no-op.
///
/// \todo Add tests when a container with push_front has been implemented.
/// \module Iterator
template <typename Container>
struct front_insert_iterator {
protected:
    Container* container_ = nullptr;

public:
    using iterator_category = output_iterator_tag;
    using value_type        = void;
    using difference_type   = void;
    using pointer           = void;
    using reference         = void;
    using container_type    = Container;

    /// \brief Initializes the underlying pointer to container with nullptr.
    constexpr front_insert_iterator() noexcept = default;

    /// \brief Initializes the underlying pointer to the container to
    /// addressof(c).
    constexpr explicit front_insert_iterator(Container& container)
        : container_ { addressof(container) }
    {
    }

    /// \brief Inserts the given value value to the container.
    constexpr auto operator=(typename Container::value_type const& value)
        -> front_insert_iterator&
    {
        container_->push_front(value);
        return *this;
    }

    /// \brief Inserts the given value value to the container.
    constexpr auto operator=(typename Container::value_type&& value)
        -> front_insert_iterator&
    {
        container_->push_front(move(value));
        return *this;
    }

    /// \brief Does nothing, this member function is provided to satisfy the
    /// requirements of LegacyOutputIterator. It returns the iterator itself,
    /// which makes it possible to use code such as *iter = value to output
    /// (insert) the value into the underlying container.
    constexpr auto operator*() -> front_insert_iterator& { return *this; }

    /// \brief Does nothing. These operator overloads are provided to satisfy
    /// the requirements of LegacyOutputIterator. They make it possible for the
    /// expressions *iter++=value and *++iter=value to be used to output
    /// (insert) a value into the underlying container.
    constexpr auto operator++() -> front_insert_iterator& { return *this; }

    /// \brief Does nothing. These operator overloads are provided to satisfy
    /// the requirements of LegacyOutputIterator. They make it possible for the
    /// expressions *iter++=value and *++iter=value to be used to output
    /// (insert) a value into the underlying container.
    constexpr auto operator++(int) -> front_insert_iterator { return *this; }
};

/// \brief front_inserter is a convenience function template that constructs a
/// front_insert_iterator for the container c with the type deduced from
/// the type of the argument.
/// \module Iterator
template <typename Container>
[[nodiscard]] constexpr auto front_inserter(Container& c)
    -> front_insert_iterator<Container>
{
    return front_insert_iterator<Container>(c);
}

} // namespace etl

#endif // TETL_ITERATOR_HPP
