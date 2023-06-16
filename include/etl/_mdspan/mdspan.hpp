// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MDSPAN_MDSPAN_HPP
#define TETL_MDSPAN_MDSPAN_HPP

#include <etl/_config/all.hpp>

#include <etl/_mdspan/default_accessor.hpp>
#include <etl/_mdspan/layout_right.hpp>
#include <etl/_type_traits/is_default_constructible.hpp>
#include <etl/_type_traits/is_object.hpp>
#include <etl/_type_traits/remove_cv.hpp>

namespace etl {

template <typename ElementType, typename Extents, typename LayoutPolicy = layout_right,
    typename AccessorPolicy = default_accessor<ElementType> >
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

    // constructors
    constexpr mdspan()
        requires((rank_dynamic() > 0) && is_default_constructible_v<data_handle_type>
                    && is_default_constructible_v<mapping_type> && is_default_constructible_v<accessor_type>)
        : acc_ {}, map_ {}, ptr_ {}
    {
    }

    constexpr mdspan(mdspan const& rhs) = default;
    constexpr mdspan(mdspan&& rhs)      = default; // NOLINT(performance-noexcept-move-constructor)

    [[nodiscard]] constexpr auto size() const noexcept -> size_type;
    [[nodiscard]] constexpr auto empty() const noexcept -> bool;

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

} // namespace etl

#endif // TETL_MDSPAN_MDSPAN_HPP
