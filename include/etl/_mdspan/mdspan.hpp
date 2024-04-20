// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MDSPAN_MDSPAN_HPP
#define TETL_MDSPAN_MDSPAN_HPP

#include <etl/_config/all.hpp>

#include <etl/_array/array.hpp>
#include <etl/_mdspan/default_accessor.hpp>
#include <etl/_mdspan/layout_left.hpp>
#include <etl/_mdspan/layout_right.hpp>
#include <etl/_span/span.hpp>
#include <etl/_type_traits/extent.hpp>
#include <etl/_type_traits/is_array.hpp>
#include <etl/_type_traits/is_constructible.hpp>
#include <etl/_type_traits/is_convertible.hpp>
#include <etl/_type_traits/is_default_constructible.hpp>
#include <etl/_type_traits/is_nothrow_constructible.hpp>
#include <etl/_type_traits/is_object.hpp>
#include <etl/_type_traits/is_pointer.hpp>
#include <etl/_type_traits/rank.hpp>
#include <etl/_type_traits/remove_all_extents.hpp>
#include <etl/_type_traits/remove_cv.hpp>
#include <etl/_type_traits/remove_pointer.hpp>
#include <etl/_type_traits/remove_reference.hpp>
#include <etl/_utility/index_sequence.hpp>
#include <etl/_utility/move.hpp>

namespace etl {

/// \ingroup mdspan
template <
    typename ElementType,
    typename Extents,
    typename LayoutPolicy   = layout_right,
    typename AccessorPolicy = default_accessor<ElementType>>
struct mdspan {
    using extents_type     = Extents;
    using layout_type      = LayoutPolicy;
    using accessor_type    = AccessorPolicy;
    using mapping_type     = typename layout_type::template mapping<extents_type>;
    using element_type     = ElementType;
    using value_type       = remove_cv_t<element_type>;
    using index_type       = typename extents_type::index_type;
    using size_type        = typename extents_type::size_type;
    using rank_type        = typename extents_type::rank_type;
    using data_handle_type = typename accessor_type::data_handle_type;
    using reference        = typename accessor_type::reference;

    [[nodiscard]] static constexpr auto rank() noexcept -> rank_type { return extents_type::rank(); }

    [[nodiscard]] static constexpr auto rank_dynamic() noexcept -> rank_type { return extents_type::rank_dynamic(); }

    [[nodiscard]] static constexpr auto static_extent(rank_type r) noexcept -> size_t
    {
        return extents_type::static_extent(r);
    }

    [[nodiscard]] constexpr auto extent(rank_type r) const noexcept -> index_type
    {
        return static_cast<index_type>(extents().extent(r));
    }

    // clang-format off

    // Constructor (1)
    constexpr mdspan()
        requires(
                (rank_dynamic() > 0)
            and is_default_constructible_v<data_handle_type>
            and is_default_constructible_v<mapping_type>
            and is_default_constructible_v<accessor_type>
        )
        : _acc {}, _map {}, _ptr {}
    {
    }

    // Constructor (2)
    template <typename... OtherSizeTypes>
        requires(
                (is_convertible_v<OtherSizeTypes, size_type> and ...)
            and (is_nothrow_constructible_v<size_type, OtherSizeTypes> and ...)
            and ((sizeof...(OtherSizeTypes) == rank()) || (sizeof...(OtherSizeTypes) == rank_dynamic()))
            and is_constructible_v<mapping_type, extents_type>
            and is_default_constructible_v<accessor_type>
        )
    explicit constexpr mdspan(data_handle_type ptr, OtherSizeTypes... exts)
        :  _map(extents_type(static_cast<size_type>(etl::move(exts))...)),_ptr(etl::move(ptr))
    {
    }

    // clang-format on

    // Constructor (5)
    constexpr mdspan(data_handle_type ptr, extents_type const& ext)
        requires(is_constructible_v<mapping_type, mapping_type const&> and is_default_constructible_v<accessor_type>)
        : _map(ext)
        , _ptr(etl::move(ptr))
    {
    }

    // Constructor (6)
    constexpr mdspan(data_handle_type ptr, mapping_type const& m)
        requires(is_default_constructible_v<accessor_type>)
        : _map(m)
        , _ptr(etl::move(ptr))
    {
    }

    // Constructor (7)
    constexpr mdspan(data_handle_type ptr, mapping_type const& m, accessor_type const& a)
        : _acc(a)
        , _map(m)
        , _ptr(etl::move(ptr))
    {
    }

    constexpr mdspan(mdspan const& rhs) = default;
    constexpr mdspan(mdspan&& rhs)      = default; // NOLINT(performance-noexcept-move-constructor)

    // clang-format off
    template <typename... OtherIndexTypes>
        requires(
                (is_convertible_v<OtherIndexTypes, index_type> && ...)
            and (is_nothrow_constructible_v<index_type, OtherIndexTypes> && ...)
            and sizeof...(OtherIndexTypes) == rank()
        )
    [[nodiscard]] constexpr auto operator()(OtherIndexTypes... indices) const -> reference
    {
        return _acc.access(_ptr, static_cast<etl::size_t>(_map(static_cast<index_type>(etl::move(indices))...)));
    }

#if defined(__cpp_multidimensional_subscript)
    template <typename... OtherIndexTypes>
        requires(
                (is_convertible_v<OtherIndexTypes, index_type> && ...)
            and (is_nothrow_constructible_v<index_type, OtherIndexTypes> && ...)
            and sizeof...(OtherIndexTypes) == rank()
        )
    [[nodiscard]] constexpr auto operator[](OtherIndexTypes... indices) const -> reference
    {
        return _acc.access(_ptr, static_cast<etl::size_t>(_map(static_cast<index_type>(etl::move(indices))...)));
    }
#endif
    // clang-format on

    template <typename OtherIndexType>
        requires(is_convertible_v<OtherIndexType const&, index_type>
                 and is_nothrow_constructible_v<index_type, OtherIndexType const&>)
    [[nodiscard]] constexpr auto operator[](span<OtherIndexType, rank()> indices) const -> reference
    {
        return [&]<size_t... Is>(index_sequence<Is...> /*seq*/) -> reference {
            return (*this)(indices[Is]...);
        }(make_index_sequence<rank()>{});
    }

    template <typename OtherIndexType>
        requires(is_convertible_v<OtherIndexType const&, index_type>
                 and is_nothrow_constructible_v<index_type, OtherIndexType const&>)
    [[nodiscard]] constexpr auto operator[](array<OtherIndexType, rank()> const& indices) const -> reference
    {
        return (*this)[etl::span{indices}];
    }

    [[nodiscard]] constexpr auto data_handle() const noexcept -> data_handle_type const& { return _ptr; }
    [[nodiscard]] constexpr auto mapping() const noexcept -> mapping_type const& { return _map; }
    [[nodiscard]] constexpr auto accessor() const noexcept -> accessor_type const& { return _acc; }

    [[nodiscard]] constexpr auto extents() const noexcept -> extents_type const& { return _map.extents(); }
    [[nodiscard]] constexpr auto stride(rank_type r) const -> index_type { return _map.stride(r); }
    [[nodiscard]] constexpr auto empty() const noexcept -> bool { return size() == size_type{}; }
    [[nodiscard]] constexpr auto size() const noexcept -> size_type
    {
        return static_cast<size_type>(detail::fwd_prod_of_extents(extents(), rank()));
    }

    [[nodiscard]] constexpr auto is_unique() const -> bool { return _map.is_unique(); }
    [[nodiscard]] constexpr auto is_exhaustive() const -> bool { return _map.is_exhaustive(); }
    [[nodiscard]] constexpr auto is_strided() const -> bool { return _map.is_strided(); }

    [[nodiscard]] static constexpr auto is_always_unique() -> bool { return mapping_type::is_always_unique(); }
    [[nodiscard]] static constexpr auto is_always_exhaustive() -> bool { return mapping_type::is_always_exhaustive(); }
    [[nodiscard]] static constexpr auto is_always_strided() -> bool { return mapping_type::is_always_strided(); }

private:
    TETL_NO_UNIQUE_ADDRESS accessor_type _acc;    // NOLINT(modernize-use-default-member-init)
    TETL_NO_UNIQUE_ADDRESS mapping_type _map;     // NOLINT(modernize-use-default-member-init)
    TETL_NO_UNIQUE_ADDRESS data_handle_type _ptr; // NOLINT(modernize-use-default-member-init)
};

template <typename CArray>
    requires(is_array_v<CArray> && rank_v<CArray> == 1)
mdspan(CArray&) -> mdspan<remove_all_extents_t<CArray>, extents<size_t, extent_v<CArray, 0>>>;

template <typename Pointer>
    requires(is_pointer_v<remove_reference_t<Pointer>>)
mdspan(Pointer&&) -> mdspan<remove_pointer_t<remove_reference_t<Pointer>>, extents<size_t>>;

template <typename ElementType, typename... Integrals>
    requires((is_convertible_v<Integrals, size_t> && ...) && sizeof...(Integrals) > 0)
explicit mdspan(ElementType*, Integrals...) -> mdspan<ElementType, dextents<size_t, sizeof...(Integrals)>>;

template <typename ElementType, typename IndexType, size_t... ExtentsPack>
mdspan(ElementType*, extents<IndexType, ExtentsPack...> const&)
    -> mdspan<ElementType, extents<IndexType, ExtentsPack...>>;

template <typename ElementType, typename MappingType>
mdspan(ElementType*, MappingType const&)
    -> mdspan<ElementType, typename MappingType::extents_type, typename MappingType::layout_type>;

template <typename MappingType, typename AccessorType>
mdspan(typename AccessorType::data_handle_type const&, MappingType const&, AccessorType const&)
    -> mdspan<
        typename AccessorType::element_type,
        typename MappingType::extents_type,
        typename MappingType::layout_type,
        AccessorType>;

} // namespace etl

#endif // TETL_MDSPAN_MDSPAN_HPP
