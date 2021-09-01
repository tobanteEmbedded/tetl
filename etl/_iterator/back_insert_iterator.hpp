/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt
#ifndef TETL_ITERATOR_BACK_INSERT_ITERATOR_HPP
#define TETL_ITERATOR_BACK_INSERT_ITERATOR_HPP

#include "etl/_cstddef/ptrdiff_t.hpp"
#include "etl/_iterator/tags.hpp"
#include "etl/_memory/addressof.hpp"
#include "etl/_utility/move.hpp"

namespace etl {

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
        : container_ { &container }
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
        container_->push_back(move(value));
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

} // namespace etl

#endif // TETL_ITERATOR_BACK_INSERT_ITERATOR_HPP