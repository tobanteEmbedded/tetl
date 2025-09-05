// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FLAT_SET_FLAT_MULTISET_HPP
#define TETL_FLAT_SET_FLAT_MULTISET_HPP

#include <etl/_config/all.hpp>

#include <etl/_algorithm/sort.hpp>
#include <etl/_flat_set/sorted_equivalent.hpp>
#include <etl/_functional/less.hpp>
#include <etl/_iterator/reverse_iterator.hpp>
#include <etl/_utility/move.hpp>

namespace etl {

template <typename Key, typename KeyContainer, typename Compare = less<Key>>
struct flat_multiset {
    using key_type               = Key;
    using value_type             = Key;
    using key_compare            = Compare;
    using value_compare          = Compare;
    using reference              = value_type&;
    using const_reference        = value_type const&;
    using size_type              = typename KeyContainer::size_type;
    using difference_type        = typename KeyContainer::difference_type;
    using iterator               = typename KeyContainer::iterator;
    using const_iterator         = typename KeyContainer::const_iterator;
    using reverse_iterator       = etl::reverse_iterator<iterator>;
    using const_reverse_iterator = etl::reverse_iterator<const_iterator>;
    using container_type         = KeyContainer;

    constexpr flat_multiset()
        : flat_multiset(Compare())
    {
    }

    explicit constexpr flat_multiset(Compare const& comp)
        : _container()
        , _compare(comp)
    {
    }

    explicit constexpr flat_multiset(KeyContainer cont)
        : flat_multiset(sorted_equivalent, etl::move(cont))
    {
        etl::sort(begin(), end(), _compare);
    }

    constexpr flat_multiset(sorted_equivalent_t /*tag*/, KeyContainer cont)
        : _container(etl::move(cont))
        , _compare()
    {
    }

    [[nodiscard]] constexpr auto begin() noexcept -> iterator
    {
        return _container.begin();
    }
    [[nodiscard]] constexpr auto begin() const noexcept -> const_iterator
    {
        return _container.begin();
    }
    [[nodiscard]] constexpr auto cbegin() const noexcept -> const_iterator
    {
        return _container.begin();
    }

    [[nodiscard]] constexpr auto end() noexcept -> iterator
    {
        return _container.end();
    }
    [[nodiscard]] constexpr auto end() const noexcept -> const_iterator
    {
        return _container.end();
    }
    [[nodiscard]] constexpr auto cend() const noexcept -> const_iterator
    {
        return _container.end();
    }

    [[nodiscard]] constexpr auto rbegin() noexcept -> reverse_iterator
    {
        return _container.rbegin();
    }
    [[nodiscard]] constexpr auto rbegin() const noexcept -> const_reverse_iterator
    {
        return _container.rbegin();
    }
    [[nodiscard]] constexpr auto crbegin() const noexcept -> const_reverse_iterator
    {
        return _container.crbegin();
    }

    [[nodiscard]] constexpr auto rend() noexcept -> reverse_iterator
    {
        return _container.rend();
    }
    [[nodiscard]] constexpr auto rend() const noexcept -> const_reverse_iterator
    {
        return _container.rend();
    }
    [[nodiscard]] constexpr auto crend() const noexcept -> const_reverse_iterator
    {
        return _container.crend();
    }

    [[nodiscard]] constexpr auto empty() const noexcept -> bool
    {
        return _container.empty();
    }
    [[nodiscard]] constexpr auto size() const noexcept -> size_type
    {
        return _container.size();
    }
    [[nodiscard]] constexpr auto max_size() const noexcept -> size_type
    {
        return _container.max_size();
    }

private:
    TETL_NO_UNIQUE_ADDRESS KeyContainer _container;
    TETL_NO_UNIQUE_ADDRESS Compare _compare;
};

} // namespace etl

#endif // TETL_FLAT_SET_FLAT_MULTISET_HPP
