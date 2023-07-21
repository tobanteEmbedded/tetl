// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MDSPAN_MDSPAN_HPP
#define TETL_MDSPAN_MDSPAN_HPP

#include <etl/_config/all.hpp>

#include <etl/_mdspan/default_accessor.hpp>
#include <etl/_mdspan/layout_right.hpp>
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
#include <etl/_utility/move.hpp>

namespace etl {

template <typename ElementType, typename Extents, typename LayoutPolicy = layout_right,
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
    [[nodiscard]] constexpr auto extent(rank_type r) const noexcept -> index_type { return extents().extent(r); }

    // clang-format off

    // Constructor (1)
    constexpr mdspan()
        requires(
                (rank_dynamic() > 0)
            and is_default_constructible_v<data_handle_type>
            and is_default_constructible_v<mapping_type>
            and is_default_constructible_v<accessor_type>
        )
        : acc_ {}, map_ {}, ptr_ {}
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
        :  map_(extents_type(static_cast<size_type>(move(exts))...)),ptr_(move(ptr))
    {
    }

    // clang-format on

    // Constructor (5)
    constexpr mdspan(data_handle_type ptr, extents_type const& ext)
        requires(is_constructible_v<mapping_type, mapping_type const&> and is_default_constructible_v<accessor_type>)
        : map_(ext), ptr_(move(ptr))
    {
    }

    // Constructor (6)
    constexpr mdspan(data_handle_type ptr, mapping_type const& m)
        requires(is_default_constructible_v<accessor_type>)
        : map_(m), ptr_(move(ptr))
    {
    }

    // Constructor (7)
    constexpr mdspan(data_handle_type ptr, mapping_type const& m, accessor_type const& a)
        : acc_(a), map_(m), ptr_(move(ptr))
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
        return acc_.access(ptr_, map_(static_cast<index_type>(move(indices))...));
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
        return acc_.access(ptr_, map_(static_cast<index_type>(move(indices))...));
    }
#endif
    // clang-format on

    [[nodiscard]] constexpr auto size() const noexcept -> size_type
    {
        return detail::fwd_prod_of_extents(extents(), rank());
    }

    [[nodiscard]] constexpr auto empty() const noexcept -> bool { return size() == size_type {}; }

    [[nodiscard]] constexpr auto extents() const noexcept -> extents_type const& { return map_.extents(); }
    [[nodiscard]] constexpr auto data_handle() const noexcept -> data_handle_type const& { return ptr_; }
    [[nodiscard]] constexpr auto mapping() const noexcept -> mapping_type const& { return map_; }
    [[nodiscard]] constexpr auto accessor() const noexcept -> accessor_type const& { return acc_; }

    static constexpr auto is_always_unique() -> bool { return mapping_type::is_always_unique(); }
    static constexpr auto is_always_exhaustive() -> bool { return mapping_type::is_always_exhaustive(); }
    static constexpr auto is_always_strided() -> bool { return mapping_type::is_always_strided(); }

    [[nodiscard]] constexpr auto is_unique() const -> bool { return map_.is_unique(); }
    [[nodiscard]] constexpr auto is_exhaustive() const -> bool { return map_.is_exhaustive(); }
    [[nodiscard]] constexpr auto is_strided() const -> bool { return map_.is_strided(); }
    [[nodiscard]] constexpr auto stride(rank_type r) const -> index_type { return map_.stride(r); }

private:
    accessor_type acc_;    // NOLINT(modernize-use-default-member-init)
    mapping_type map_;     // NOLINT(modernize-use-default-member-init)
    data_handle_type ptr_; // NOLINT(modernize-use-default-member-init)
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
    -> mdspan<typename AccessorType::element_type, typename MappingType::extents_type,
        typename MappingType::layout_type, AccessorType>;

} // namespace etl

#endif // TETL_MDSPAN_MDSPAN_HPP
