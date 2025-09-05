// SPDX-License-Identifier: BSL-1.0
#ifndef TETL_ITERATOR_FRONT_INSERT_ITERATOR_HPP
#define TETL_ITERATOR_FRONT_INSERT_ITERATOR_HPP

#include <etl/_iterator/tags.hpp>
#include <etl/_memory/addressof.hpp>
#include <etl/_utility/move.hpp>

namespace etl {

/// front_insert_iterator is an LegacyOutputIterator that prepends
/// elements to a container for which it was constructed.
///
/// The container's push_front() member function is called whenever the
/// iterator (whether dereferenced or not) is assigned to. Incrementing the
/// front_insert_iterator is a no-op.
///
/// \ingroup iterator
template <typename Container>
struct front_insert_iterator {
protected:
    Container* _container = nullptr;

public:
    using iterator_category = output_iterator_tag;
    using value_type        = void;
    using difference_type   = void;
    using pointer           = void;
    using reference         = void;
    using container_type    = Container;

    /// Initializes the underlying pointer to container with nullptr.
    constexpr front_insert_iterator() noexcept = default;

    /// Initializes the underlying pointer to the container to addressof(c).
    constexpr explicit front_insert_iterator(Container& container)
        : _container{etl::addressof(container)}
    {
    }

    /// Inserts the given value value to the container.
    constexpr auto operator=(typename Container::value_type const& value) -> front_insert_iterator&
    {
        _container->push_front(value);
        return *this;
    }

    /// Inserts the given value value to the container.
    constexpr auto operator=(typename Container::value_type&& value) -> front_insert_iterator&
    {
        _container->push_front(etl::move(value));
        return *this;
    }

    /// Does nothing, this member function is provided to satisfy the
    /// requirements of LegacyOutputIterator. It returns the iterator itself,
    /// which makes it possible to use code such as *iter = value to output
    /// (insert) the value into the underlying container.
    constexpr auto operator*() -> front_insert_iterator&
    {
        return *this;
    }

    /// Does nothing. These operator overloads are provided to satisfy
    /// the requirements of LegacyOutputIterator. They make it possible for the
    /// expressions *iter++=value and *++iter=value to be used to output
    /// (insert) a value into the underlying container.
    constexpr auto operator++() -> front_insert_iterator&
    {
        return *this;
    }

    /// Does nothing. These operator overloads are provided to satisfy
    /// the requirements of LegacyOutputIterator. They make it possible for the
    /// expressions *iter++=value and *++iter=value to be used to output
    /// (insert) a value into the underlying container.
    constexpr auto operator++(int) -> front_insert_iterator
    {
        return *this;
    }
};

/// front_inserter is a convenience function template that constructs a
/// front_insert_iterator for the container c with the type deduced from
/// the type of the argument.
template <typename Container>
[[nodiscard]] constexpr auto front_inserter(Container& c) -> front_insert_iterator<Container>
{
    return front_insert_iterator<Container>(c);
}

} // namespace etl

#endif // TETL_ITERATOR_FRONT_INSERT_ITERATOR_HPP
