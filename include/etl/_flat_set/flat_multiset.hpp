// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_FLAT_SET_FLAT_MULTISET_HPP
#define TETL_FLAT_SET_FLAT_MULTISET_HPP

#include <etl/_config/all.hpp>

#include <etl/_flat_set/sorted_unique.hpp>
#include <etl/_functional/less.hpp>
#include <etl/_iterator/reverse_iterator.hpp>

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

    [[nodiscard]] constexpr auto empty() const noexcept -> bool { return _container.empty(); }
    [[nodiscard]] constexpr auto size() const noexcept -> size_type { return _container.size(); }
    [[nodiscard]] constexpr auto max_size() const noexcept -> size_type { return _container.max_size(); }

    [[nodiscard]] constexpr auto begin() -> iterator { return _container.begin(); }
    [[nodiscard]] constexpr auto begin() const -> const_iterator { return _container.begin(); }
    [[nodiscard]] constexpr auto cbegin() const -> const_iterator { return _container.begin(); }

    [[nodiscard]] constexpr auto end() -> iterator { return _container.end(); }
    [[nodiscard]] constexpr auto end() const -> const_iterator { return _container.end(); }
    [[nodiscard]] constexpr auto cend() const -> const_iterator { return _container.end(); }

    [[nodiscard]] constexpr auto rbegin() -> reverse_iterator { return reverse_iterator(end()); }
    [[nodiscard]] constexpr auto rbegin() const -> const_reverse_iterator { return const_reverse_iterator(end()); }
    [[nodiscard]] constexpr auto crbegin() const -> const_reverse_iterator { return const_reverse_iterator(end()); }

    [[nodiscard]] constexpr auto rend() -> reverse_iterator { return reverse_iterator(begin()); }
    [[nodiscard]] constexpr auto rend() const -> const_reverse_iterator { return const_reverse_iterator(begin()); }
    [[nodiscard]] constexpr auto crend() const -> const_reverse_iterator { return const_reverse_iterator(begin()); }

private:
    TETL_NO_UNIQUE_ADDRESS KeyContainer _container;
    TETL_NO_UNIQUE_ADDRESS Compare _compare;
};

} // namespace etl

#endif // TETL_FLAT_SET_FLAT_MULTISET_HPP
