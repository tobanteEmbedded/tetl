// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ARRAY_MDARRAY_HPP
#define TETL_ARRAY_MDARRAY_HPP

#include <etl/_mdspan/mdspan.hpp>
#include <etl/_memory/to_address.hpp>
#include <etl/_type_traits/declval.hpp>

namespace etl {

/// \ingroup mdarray
template <typename ElementType, typename Extents, typename LayoutPolicy, typename Container>
struct mdarray {
    using extents_type      = Extents;
    using layout_type       = LayoutPolicy;
    using container_type    = Container;
    using mapping_type      = typename layout_type::template mapping<extents_type>;
    using element_type      = ElementType;
    using mdspan_type       = mdspan<element_type, extents_type, layout_type>;
    using const_mdspan_type = mdspan<element_type const, extents_type, layout_type>;
    using value_type        = element_type;
    using index_type        = typename Extents::index_type;
    using size_type         = typename Extents::size_type;
    using rank_type         = typename Extents::rank_type;
    using pointer           = decltype(etl::to_address(etl::declval<container_type>().begin()));
    using reference         = typename container_type::reference;
    using const_pointer     = decltype(etl::to_address(etl::declval<container_type>().cbegin()));
    using const_reference   = typename container_type::const_reference;

    [[nodiscard]] static constexpr auto rank() noexcept -> rank_type { return Extents::rank(); }

    [[nodiscard]] static constexpr auto rank_dynamic() noexcept -> rank_type { return Extents::rank_dynamic(); }

    [[nodiscard]] static constexpr auto static_extent(rank_type r) noexcept -> size_t
    {
        return Extents::static_extent(r);
    }

    [[nodiscard]] constexpr auto extent(rank_type r) const noexcept -> index_type { return extents().extent(r); }

    // [mdarray.ctors], mdarray constructors
    constexpr mdarray()
        requires(rank_dynamic() != 0)
    = default;
    constexpr mdarray(mdarray const& rhs) = default;
    constexpr mdarray(mdarray&& rhs)      = default;

    // template <typename... OtherIndexTypes>
    // explicit constexpr mdarray(OtherIndexTypes... exts);
    // explicit constexpr mdarray(extents_type const& ext);
    // explicit constexpr mdarray(mapping_type const& m);

    // constexpr mdarray(extents_type const& ext, value_type const& val);
    // constexpr mdarray(mapping_type const& m, value_type const& val);

    // constexpr mdarray(extents_type const& ext, container_type const& c);
    // constexpr mdarray(mapping_type const& m, container_type const& c, );

    // constexpr mdarray(extents_type const& ext, container_type&& c);
    // constexpr mdarray(mapping_type const& m, container_type&& c, );

    // template <typename OtherElementType, typename OtherExtents, typename OtherLayoutPolicy,
    // typename OtherContainer> explicit(see below) constexpr mdarray(
    //     mdarray<OtherElementType, OtherExtents, OtherLayoutPolicy, OtherContainer> const& other);

    // template <typename OtherElementType, typename OtherExtents, typename OtherLayoutPolicy,
    // typename Accessor> explicit(see below) constexpr mdarray(
    //     mdspan<OtherElementType, OtherExtents, OtherLayoutPolicy, Accessor> const& other);

    // // [mdarray.ctors.alloc], mdarray constructors with allocators
    // template <typename Alloc>
    // constexpr mdarray(extents_type const& ext, Alloc const& a);
    // template <typename Alloc>
    // constexpr mdarray(mapping_type const& m, Alloc const& a);

    // template <typename Alloc>
    // constexpr mdarray(extents_type const& ext, value_type const& val, Alloc const& a);
    // template <typename Alloc>
    // constexpr mdarray(mapping_type const& m, value_type const& val, Alloc const& a);

    // template <typename Alloc>
    // constexpr mdarray(extents_type const& ext, container_type const& c, Alloc const& a);
    // template <typename Alloc>
    // constexpr mdarray(mapping_type const& m, container_type const& c, Alloc const& a);

    // template <typename Alloc>
    // constexpr mdarray(extents_type const& ext, container_type&& c, Alloc const& a);
    // template <typename Alloc>
    // constexpr mdarray(mapping_type const& m, container_type&& c, Alloc const& a);

    // template <typename OtherElementType, typename OtherExtents, typename OtherLayoutPolicy,
    // typename OtherContainer,
    //     typename Alloc>
    // explicit(see below) constexpr mdarray(
    //     mdarray<OtherElementType, OtherExtents, OtherLayoutPolicy, OtherContainer> const& other,
    //     Alloc const& a);

    // template <typename OtherElementType, typename OtherExtents, typename OtherLayoutPolicy,
    // typename Accessor,
    //     typename Alloc>
    // explicit(see below) constexpr mdarray(
    //     mdspan<OtherElementType, OtherExtents, OtherLayoutPolicy, Accessor> const& other, Alloc
    //     const& a);

    // constexpr mdarray& operator=(mdarray const& rhs) = default;
    // constexpr mdarray& operator=(mdarray&& rhs)      = default;

    // // [mdarray.members], mdarray members
    // template <typename... OtherIndexTypes>
    // constexpr reference operator[](OtherIndexTypes... indices);
    // template <typename OtherIndexType>
    // constexpr reference operator[](span<OtherIndexType, rank()> indices);
    // template <typename OtherIndexType>
    // constexpr reference operator[](array<OtherIndexType, rank()> const& indices);
    // template <typename... OtherIndexTypes>
    // constexpr const_reference operator[](OtherIndexTypes... indices) const;
    // template <typename OtherIndexType>
    // constexpr const_reference operator[](span<OtherIndexType, rank()> indices) const;
    // template <typename OtherIndexType>
    // constexpr const_reference operator[](array<OtherIndexType, rank()> const& indices) const;

    // constexpr size_type size() const;
    // [[nodiscard]] constexpr bool empty() const noexcept;
    [[nodiscard]] constexpr auto container_size() const { return _ctr.size(); }

    // friend constexpr void swap(mdarray& x, mdarray& y) noexcept;

    [[nodiscard]] constexpr auto extents() const -> extents_type const& { return _map.extents(); }

    [[nodiscard]] constexpr auto container_data() -> pointer { return to_address(_ctr.begin()); }

    [[nodiscard]] constexpr auto container_data() const -> const_pointer { return to_address(_ctr.cbegin()); }

    [[nodiscard]] constexpr auto mapping() const -> mapping_type const& { return _map; }

    // template <typename OtherElementType, typename OtherExtents, typename OtherLayoutType, typename
    // OtherAccessorType> constexpr operator mdspan() const;

    // template <typename OtherAccessorType = default_accessor<element_type>>
    // constexpr mdspan<element_type, extents_type, layout_type, OtherAccessorType> to_mdspan(
    //     OtherAccessorType const& a = default_accessor<element_type>());
    // template <typename OtherAccessorType = default_accessor<element_type const>>
    // constexpr mdspan<const element_type, extents_type, layout_type, OtherAccessorType> to_mdspan(
    //     OtherAccessorType const& a = default_accessor<const_element_type>()) const;

    [[nodiscard]] auto extract_container() && -> container_type&& { return etl::move(_ctr); }

    [[nodiscard]] static constexpr auto is_always_unique() -> bool { return mapping_type::is_always_unique(); }

    [[nodiscard]] static constexpr auto is_always_exhaustive() -> bool { return mapping_type::is_always_exhaustive(); }

    [[nodiscard]] static constexpr auto is_always_strided() -> bool { return mapping_type::is_always_strided(); }

    [[nodiscard]] constexpr auto is_unique() const -> bool { return _map.is_unique(); }

    [[nodiscard]] constexpr auto is_exhaustive() const -> bool { return _map.is_exhaustive(); }

    [[nodiscard]] constexpr auto is_strided() const -> bool { return _map.is_strided(); }

    [[nodiscard]] constexpr auto stride(etl::size_t r) const -> index_type { return _map.stride(r); }

private:
    container_type _ctr;
    mapping_type _map;
};

} // namespace etl

#endif // TETL_ARRAY_MDARRAY_HPP
