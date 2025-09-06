// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2023 Tobias Hienzsch

#ifndef TETL_ARRAY_MDARRAY_HPP
#define TETL_ARRAY_MDARRAY_HPP

#include <etl/_array/array.hpp>
#include <etl/_iterator/size.hpp>
#include <etl/_mdspan/mdspan.hpp>
#include <etl/_memory/to_address.hpp>
#include <etl/_span/span.hpp>
#include <etl/_type_traits/declval.hpp>
#include <etl/_type_traits/is_assignable.hpp>
#include <etl/_type_traits/is_constructible.hpp>
#include <etl/_type_traits/is_convertible.hpp>
#include <etl/_type_traits/is_nothrow_constructible.hpp>
#include <etl/_utility/as_const.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/index_sequence.hpp>
#include <etl/_utility/move.hpp>

namespace etl {

/// \ingroup mdarray
template <typename ElementType, typename Extents, typename LayoutPolicy, typename Container>
struct mdarray {
private:
    template <typename C, typename... Args>
    static constexpr auto array_or_constructible_from = is_etl_array<C> or is_constructible_v<C, Args...>;

public:
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

    [[nodiscard]] static constexpr auto rank() noexcept -> rank_type
    {
        return Extents::rank();
    }
    [[nodiscard]] static constexpr auto rank_dynamic() noexcept -> rank_type
    {
        return Extents::rank_dynamic();
    }
    [[nodiscard]] static constexpr auto static_extent(rank_type r) noexcept -> size_t
    {
        return Extents::static_extent(r);
    }
    [[nodiscard]] constexpr auto extent(rank_type r) const noexcept -> index_type
    {
        return extents().extent(r);
    }

    // [mdarray.ctors], mdarray constructors
    constexpr mdarray()
        requires(rank_dynamic() != 0)
    = default;
    constexpr mdarray(mdarray const& rhs) = default;
    constexpr mdarray(mdarray&& rhs)      = default;

    template <typename... OtherIndexTypes>
        requires(
            (is_convertible_v<OtherIndexTypes, index_type> and ...)
            and (is_nothrow_constructible_v<index_type, OtherIndexTypes> and ...)
            and (is_constructible_v<extents_type, OtherIndexTypes...>)
            and (is_constructible_v<mapping_type, extents_type>)
            and (array_or_constructible_from<Container, size_t>)
        )
    explicit constexpr mdarray(OtherIndexTypes... exts)
        : mdarray(extents_type(static_cast<index_type>(etl::move(exts))...))
    {
    }

    explicit constexpr mdarray(extents_type const& ext)
        requires(
            is_constructible_v<mapping_type, extents_type const&> and array_or_constructible_from<Container, size_t>
        )
        : mdarray(mapping_type(ext))
    {
    }

    explicit constexpr mdarray(mapping_type const& m)
        requires(array_or_constructible_from<Container, size_t>)
        : _map(m)
        , _ctr([&]() -> container_type {
            if constexpr (is_constructible_v<Container, size_t>) {
                return container_type(static_cast<size_t>(_map.required_span_size()));
            } else {
                return {};
            }
        }())
    {
    }

    constexpr mdarray(extents_type const& ext, value_type const& val)
        requires(
            is_constructible_v<mapping_type, extents_type const&>
            and array_or_constructible_from<Container, size_t, value_type>
        )
        : mdarray(mapping_type(ext), val)
    {
    }

    constexpr mdarray(mapping_type const& m, value_type const& val)
        requires(array_or_constructible_from<Container, size_t, value_type>)
        : _map(m)
        , _ctr([&]() -> container_type {
            if constexpr (is_constructible_v<Container, size_t, value_type>) {
                return container_type(static_cast<size_t>(_map.required_span_size()), val);
            } else {
                return value_to_array<element_type, container_type().size()>(val);
            }
        }())
    {
    }

    constexpr mdarray(extents_type const& ext, container_type const& c)
        requires(is_constructible_v<mapping_type, extents_type const&>)
        : mdarray(mapping_type(ext), c)
    {
    }

    constexpr mdarray(mapping_type const& m, container_type const& c)
        : _map(m)
        , _ctr(c)
    {
    }

    constexpr mdarray(extents_type const& ext, container_type&& c)
        requires(is_constructible_v<mapping_type, extents_type const&>)
        : mdarray(mapping_type(ext), etl::move(c))
    {
    }

    constexpr mdarray(mapping_type const& m, container_type&& c)
        : _map(m)
        , _ctr(etl::move(c))
    {
    }

    // template <typename OtherElementType, typename OtherExtents, typename OtherLayoutPolicy,
    // typename OtherContainer> explicit(see below) constexpr mdarray(
    //     mdarray<OtherElementType, OtherExtents, OtherLayoutPolicy, OtherContainer> const& other);

    // template <typename OtherElementType, typename OtherExtents, typename OtherLayoutPolicy,
    // typename Accessor> explicit(see below) constexpr mdarray(
    //     mdspan<OtherElementType, OtherExtents, OtherLayoutPolicy, Accessor> const& other);

    constexpr auto operator=(mdarray const& rhs) -> mdarray& = default;
    constexpr auto operator=(mdarray&& rhs) -> mdarray&      = default;

#if defined(__cpp_multidimensional_subscript)
    template <typename... OtherIndexTypes>
        requires(
            (is_convertible_v<OtherIndexTypes, index_type> and ...)
            and (is_nothrow_constructible_v<index_type, OtherIndexTypes> and ...)
            and (sizeof...(OtherIndexTypes) == rank())
        )
    [[nodiscard]] constexpr auto operator[](OtherIndexTypes... indices) -> reference
    {
        return (*this)(etl::move(indices)...);
    }

    template <typename... OtherIndexTypes>
        requires(
            (is_convertible_v<OtherIndexTypes, index_type> and ...)
            and (is_nothrow_constructible_v<index_type, OtherIndexTypes> and ...)
            and (sizeof...(OtherIndexTypes) == rank())
        )
    [[nodiscard]] constexpr auto operator[](OtherIndexTypes... indices) const -> const_reference
    {
        return (*this)(etl::move(indices)...);
    }
#endif

    template <typename... OtherIndexTypes>
        requires(
            (is_convertible_v<OtherIndexTypes, index_type> and ...)
            and (is_nothrow_constructible_v<index_type, OtherIndexTypes> and ...)
            and (sizeof...(OtherIndexTypes) == rank())
        )
    [[nodiscard]] constexpr auto operator()(OtherIndexTypes... indices) -> reference
    {
        return _ctr[static_cast<size_t>(_map(static_cast<index_type>(etl::move(indices))...))];
    }

    template <typename... OtherIndexTypes>
        requires(
            (is_convertible_v<OtherIndexTypes, index_type> and ...)
            and (is_nothrow_constructible_v<index_type, OtherIndexTypes> and ...)
            and (sizeof...(OtherIndexTypes) == rank())
        )
    [[nodiscard]] constexpr auto operator()(OtherIndexTypes... indices) const -> const_reference
    {
        return _ctr[static_cast<size_t>(_map(static_cast<index_type>(etl::move(indices))...))];
    }

    template <typename OtherIndexType>
        requires(
            is_convertible_v<OtherIndexType const&, index_type>
            and is_nothrow_constructible_v<index_type, OtherIndexType const&>
        )
    [[nodiscard]] constexpr auto operator[](span<OtherIndexType, rank()> indices) -> reference
    {
        return [&]<size_t... Is>(index_sequence<Is...> /*seq*/) -> decltype(auto) {
            return (*this)(etl::as_const(indices[Is])...);
        }(make_index_sequence<rank()>());
    }

    template <typename OtherIndexType>
        requires(
            is_convertible_v<OtherIndexType const&, index_type>
            and is_nothrow_constructible_v<index_type, OtherIndexType const&>
        )
    [[nodiscard]] constexpr auto operator[](span<OtherIndexType, rank()> indices) const -> const_reference
    {
        return [&]<size_t... Is>(index_sequence<Is...> /*seq*/) -> decltype(auto) {
            return (*this)(etl::as_const(indices[Is])...);
        }(make_index_sequence<rank()>());
    }

    template <typename OtherIndexType>
        requires(
            is_convertible_v<OtherIndexType const&, index_type>
            and is_nothrow_constructible_v<index_type, OtherIndexType const&>
        )
    [[nodiscard]] constexpr auto operator[](array<OtherIndexType, rank()> const& indices) -> reference
    {
        return operator[](span{indices});
    }

    template <typename OtherIndexType>
        requires(
            is_convertible_v<OtherIndexType const&, index_type>
            and is_nothrow_constructible_v<index_type, OtherIndexType const&>
        )
    [[nodiscard]] constexpr auto operator[](array<OtherIndexType, rank()> const& indices) const -> const_reference
    {
        return operator[](span{indices});
    }

    [[nodiscard]] constexpr auto size() const -> size_type
    {
        return size_type(extents().fwd_prod_of_extents(rank()));
    }
    [[nodiscard]] constexpr auto empty() const noexcept -> bool
    {
        return size() == 0;
    }

    [[nodiscard]] constexpr auto extents() const -> extents_type const&
    {
        return _map.extents();
    }
    [[nodiscard]] constexpr auto mapping() const -> mapping_type const&
    {
        return _map;
    }
    [[nodiscard]] constexpr auto stride(size_t r) const -> index_type
    {
        return _map.stride(r);
    }

    [[nodiscard]] constexpr auto container_size() const
    {
        return _ctr.size();
    }
    [[nodiscard]] constexpr auto container_data() -> pointer
    {
        return to_address(_ctr.begin());
    }
    [[nodiscard]] constexpr auto container_data() const -> const_pointer
    {
        return to_address(_ctr.cbegin());
    }
    [[nodiscard]] constexpr auto extract_container() && -> container_type&&
    {
        return etl::move(_ctr);
    }

    [[nodiscard]] constexpr auto is_unique() const -> bool
    {
        return _map.is_unique();
    }
    [[nodiscard]] constexpr auto is_exhaustive() const -> bool
    {
        return _map.is_exhaustive();
    }
    [[nodiscard]] constexpr auto is_strided() const -> bool
    {
        return _map.is_strided();
    }

    [[nodiscard]] static constexpr auto is_always_unique() -> bool
    {
        return mapping_type::is_always_unique();
    }
    [[nodiscard]] static constexpr auto is_always_exhaustive() -> bool
    {
        return mapping_type::is_always_exhaustive();
    }
    [[nodiscard]] static constexpr auto is_always_strided() -> bool
    {
        return mapping_type::is_always_strided();
    }

    template <typename OtherElement, typename OtherExtents, typename OtherLayout, typename OtherAccessor>
    // requires is_assignable_v<mdspan<OtherElement, OtherExtents, OtherLayout, OtherAccessor>, mdspan_type>
    [[nodiscard]] constexpr operator mdspan<OtherElement, OtherExtents, OtherLayout, OtherAccessor>()
    {
        return mdspan_type(container_data(), _map);
    }

    template <typename OtherElement, typename OtherExtents, typename OtherLayout, typename OtherAccessor>
    // requires is_assignable_v<mdspan<OtherElement, OtherExtents, OtherLayout, OtherAccessor>, const_mdspan_type>
    [[nodiscard]] constexpr operator mdspan<OtherElement, OtherExtents, OtherLayout, OtherAccessor>() const
    {
        return const_mdspan_type(container_data(), _map);
    }

    template <typename OtherAccessor = default_accessor<element_type>>
    // requires is_assignable_v<typename OtherAccessor::data_handle_type, pointer>
    [[nodiscard]] constexpr auto to_mdspan(OtherAccessor const& a = default_accessor<element_type>())
        -> mdspan<element_type, extents_type, layout_type, OtherAccessor>
    {
        return mdspan<element_type, extents_type, layout_type, OtherAccessor>(container_data(), _map, a);
    }

    template <typename OtherAccessor = default_accessor<element_type const>>
    // requires is_assignable_v<typename OtherAccessor::data_handle_type, const_pointer>
    [[nodiscard]] constexpr auto to_mdspan(OtherAccessor const& a = default_accessor<element_type const>()) const
        -> mdspan<element_type const, extents_type, layout_type, OtherAccessor>
    {
        return mdspan<element_type const, extents_type, layout_type, OtherAccessor>(container_data(), _map, a);
    }

    friend constexpr void swap(mdarray& lhs, mdarray& rhs) noexcept
    {
        swap(lhs._map, rhs._map);
        swap(lhs._ctr, rhs._ctr);
    }

private:
    template <typename Value, size_t N>
    [[nodiscard]] static constexpr auto value_to_array(Value const& t) -> array<Value, N>
    {
        constexpr auto value = []<typename V>(auto /*i*/, V&& v) -> decltype(auto) { return etl::forward<V&&>(v); };
        return [&]<size_t... Indices>(index_sequence<Indices...>) {
            return array<Value, N>{value(Indices, t)...};
        }(make_index_sequence<N>());
    }

    mapping_type _map;
    container_type _ctr;
};

} // namespace etl

#endif // TETL_ARRAY_MDARRAY_HPP
