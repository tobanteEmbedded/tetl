// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_MDSPAN_LAYOUT_STRIDE_HPP
#define TETL_MDSPAN_LAYOUT_STRIDE_HPP

#include <etl/_array/array.hpp>
#include <etl/_contracts/check.hpp>
#include <etl/_mdspan/extents.hpp>
#include <etl/_mdspan/is_extents.hpp>
#include <etl/_mdspan/layout.hpp>
#include <etl/_span/span.hpp>
#include <etl/_type_traits/is_convertible.hpp>
#include <etl/_type_traits/is_nothrow_constructible.hpp>
#include <etl/_utility/index_sequence.hpp>

namespace etl {

template <typename Extents>
struct layout_stride::mapping {
    using extents_type = Extents;
    using index_type   = typename extents_type::index_type;
    using size_type    = typename extents_type::size_type;
    using rank_type    = typename extents_type::rank_type;
    using layout_type  = layout_stride;

private:
    static constexpr auto rank = extents_type::rank();

public:
    constexpr mapping() noexcept               = default;
    constexpr mapping(mapping const&) noexcept = default;

    template <typename OtherIndexType>
        requires(is_convertible_v<OtherIndexType const&, index_type>
                 and is_nothrow_constructible_v<index_type, OtherIndexType const&>)
    constexpr mapping(extents_type const& ext, span<OtherIndexType, rank> s) noexcept
        : _extents(ext)
        , _strides([s] {
            auto val = array<index_type, rank>{};
            etl::transform(s.begin(), s.end(), val.begin(), [](auto const& v) { return static_cast<index_type>(v); });
            return val;
        }())
    {
    }

    template <typename OtherIndexType>
        requires(is_convertible_v<OtherIndexType const&, index_type> and is_nothrow_constructible_v<index_type, OtherIndexType const&>)
    constexpr mapping(extents_type const& ext, array<OtherIndexType, rank> const& s) noexcept
        : mapping(ext, span{s})
    {
    }

    template <typename StridedLayoutMapping>
    constexpr explicit(false /* see description */) mapping(StridedLayoutMapping const&) noexcept;

    constexpr auto operator=(mapping const&) noexcept -> mapping& = default;

    [[nodiscard]] constexpr auto required_span_size() const noexcept -> index_type;
    [[nodiscard]] constexpr auto extents() const noexcept -> extents_type const& { return _extents; }
    [[nodiscard]] constexpr auto strides() const noexcept -> array<index_type, rank> { return _strides; }
    [[nodiscard]] constexpr auto stride(rank_type i) const noexcept -> index_type
    {
        TETL_PRECONDITION(i < extents_type::rank());
        return _strides[i];
    }

    template <typename... Indices>
        requires((sizeof...(Indices) == rank)                        //
                 and (is_convertible_v<Indices, index_type> and ...) //
                 and (is_nothrow_constructible_v<index_type, Indices> and ...))
    [[nodiscard]] constexpr auto operator()(Indices... is) const noexcept -> index_type
    {
        return [&]<size_t... Is>(index_sequence<Is...> /*seq*/) {
            return static_cast<index_type>(((static_cast<index_type>(is) * _strides[Is]) + ... + index_type(0)));
        }(index_sequence_for<Indices...>{});
    }

    [[nodiscard]] static constexpr auto is_always_unique() noexcept -> bool { return true; }
    [[nodiscard]] static constexpr auto is_always_strided() noexcept -> bool { return true; }
    [[nodiscard]] static constexpr auto is_always_exhaustive() noexcept -> bool { return false; }

    [[nodiscard]] static constexpr auto is_unique() noexcept -> bool { return true; }
    [[nodiscard]] static constexpr auto is_strided() noexcept -> bool { return true; }
    [[nodiscard]] constexpr auto is_exhaustive() const noexcept -> bool;

    template <typename OtherMapping>
    friend constexpr auto operator==(mapping const&, OtherMapping const&) noexcept -> bool;

private:
    TETL_NO_UNIQUE_ADDRESS extents_type _extents{};
    TETL_NO_UNIQUE_ADDRESS array<index_type, rank> _strides{};
};

} // namespace etl

#endif // TETL_MDSPAN_LAYOUT_STRIDE_HPP
