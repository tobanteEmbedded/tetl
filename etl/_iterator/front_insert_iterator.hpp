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
#ifndef TETL_ITERATOR_FRONT_INSERT_ITERATOR_HPP
#define TETL_ITERATOR_FRONT_INSERT_ITERATOR_HPP

#include "etl/_iterator/tags.hpp"
#include "etl/_memory/addressof.hpp"
#include "etl/_utility/move.hpp"

namespace etl {

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

#endif // TETL_ITERATOR_FRONT_INSERT_ITERATOR_HPP