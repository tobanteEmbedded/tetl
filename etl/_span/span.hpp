// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_SPAN_SPAN_HPP
#define TETL_SPAN_SPAN_HPP

#include "etl/_array/array.hpp"
#include "etl/_iterator/begin.hpp"
#include "etl/_iterator/data.hpp"
#include "etl/_iterator/end.hpp"
#include "etl/_iterator/rbegin.hpp"
#include "etl/_iterator/rend.hpp"
#include "etl/_iterator/size.hpp"
#include "etl/_limits/numeric_limits.hpp"
#include "etl/_span/dynamic_extent.hpp"
#include "etl/_type_traits/declval.hpp"
#include "etl/_type_traits/remove_pointer.hpp"

namespace etl {

/// \brief A non-owning view over a contiguous sequence of objects.
///
/// \details The class template span describes an object that can refer to a
/// contiguous sequence of objects with the first element of the sequence at
/// position zero. A span can either have a static extent, in which case the
/// number of elements in the sequence is known and encoded in the type, or a
/// dynamic extent.
///
/// If a span has dynamic extent a typical implementation holds
/// two members: a pointer to T and a size. A span with static extent may have
/// only one member: a pointer to T.
/// \module Containers
template <typename ElementType, size_t Extent = etl::dynamic_extent>
struct span {
    using element_type    = ElementType;
    using value_type      = etl::remove_cv_t<ElementType>;
    using size_type       = etl::size_t;
    using difference_type = etl::ptrdiff_t;
    using pointer         = ElementType*;
    using const_pointer   = ElementType const*;
    using reference       = ElementType&;
    using const_reference = ElementType const&;
    using iterator        = ElementType const*;
    // using reverse_iterator = etl::reverse_iterator<iterator>;

    /// \brief The number of elements in the sequence, or etl::dynamic_extent
    /// if dynamic.
    static constexpr size_type extent = Extent;

    /// \brief Constructs a span. Constructs an empty span whose
    /// data() == nullptr and size() == 0.
    ///
    /// \details This overload only participates in overload resolution
    /// if extent == 0 || extent == etl::dynamic_extent.
    ///
    /// \todo Remove from overload with concepts once available.
    constexpr span() noexcept = default;

    /// \brief Constructs a span.
    ///
    /// \details Constructs a span that is a view over the range [first, first +
    /// count); the resulting span has data() == etl::to_address(first) and
    /// size()
    /// == count. The behavior is undefined if [first, first + count) is not a
    /// valid range, if It does not actually model contiguous_iterator, or if
    /// extent != etl::dynamic_extent && count != extent. This overload only
    /// participates in overload resolution if, It satisfies contiguous_iterator
    /// and the conversion from etl::iter_reference_t<It> to element_type is at
    /// most a qualification conversion.
    ///
    /// \todo Add explicit(extent != etl::dynamic_extent).
    template <typename It>
    constexpr span(It first, size_type count) : data_ { first }, size_ { count }
    {
    }

    // /// \brief Constructs a span.
    // /// \todo Add explicit(extent != etl::dynamic_extent).
    // template <typename It, typename End>
    // constexpr span(It first, End last);

    /// \brief Constructs a span. From a c style array.
    template <etl::size_t N>
    constexpr span(element_type (&arr)[N]) noexcept
        : data_ { &arr[0] }, size_ { N }
    {
    }

    /// \brief Constructs a span. From a etl::array<Type,Size>.
    template <typename U, etl::size_t N>
    constexpr span(etl::array<U, N>& arr) noexcept
        : data_ { arr.data() }, size_ { arr.size() }
    {
    }

    /// \brief Constructs a span. From a etl::array<Type,Size> const.
    template <typename U, etl::size_t N>
    constexpr span(etl::array<U, N> const& arr) noexcept
        : data_ { arr.data() }, size_ { arr.size() }
    {
    }

    /// \brief Constructs a span.
    ///
    /// \todo Add explicit(extent != etl::dynamic_extent)
    template <typename R>
    constexpr span(R&& r) : data_ { r.data() }, size_ { r.size() }
    {
    }

    // /// \brief Constructs a span.
    // template <typename U, etl::size_t N>
    // explicit(extent != etl::dynamic_extent
    //          && N == etl::dynamic_extent) constexpr span( etl::span<U,
    //          N> const& s) noexcept;

    /// \brief Constructs a span.
    constexpr span(span const& other) noexcept = default;

    /// \brief Returns an iterator to the first element of the span. If the span
    /// is empty, the returned iterator will be equal to end().
    [[nodiscard]] constexpr auto begin() const noexcept -> iterator
    {
        return &data_[0];
    }

    /// \brief Returns an iterator to the element following the last element of
    /// the span. This element acts as a placeholder; attempting to access it
    /// results in undefined behavior
    [[nodiscard]] constexpr auto end() const noexcept -> iterator
    {
        return begin() + size();
    }

    /// \brief Returns a reference to the first element in the span. Calling
    /// front on an empty span results in undefined behavior.
    [[nodiscard]] constexpr auto front() const -> reference { return *begin(); }

    /// \brief Returns a reference to the last element in the span. Calling
    /// front on an empty span results in undefined behavior.
    [[nodiscard]] constexpr auto back() const -> reference
    {
        return *(end() - 1);
    }

    /// \brief Returns a reference to the idx-th element of the sequence. The
    /// behavior is undefined if idx is out of range (i.e., if it is greater
    /// than or equal to size()).
    [[nodiscard]] constexpr auto operator[](size_type idx) const -> reference
    {
        return data()[idx];
    }

    /// \brief Returns a pointer to the beginning of the sequence.
    [[nodiscard]] constexpr auto data() const noexcept -> pointer
    {
        return data_;
    }

    /// \brief Returns the number of elements in the span.
    [[nodiscard]] constexpr auto size() const noexcept -> size_type
    {
        return size_;
    }

    /// \brief Returns the number of elements in the span.
    [[nodiscard]] constexpr auto size_bytes() const noexcept -> size_type
    {
        return size() * sizeof(element_type);
    }

    /// \brief Checks if the span is empty.
    [[nodiscard]] constexpr auto empty() const noexcept -> bool
    {
        return size() == 0;
    }

private:
    pointer data_   = nullptr;
    size_type size_ = 0;
};

// Deduction Guides. From raw array.
template <typename Type, etl::size_t Extent>
span(Type (&)[Extent]) -> span<Type, Extent>;

// Deduction Guides. From etl::array<Type, Size>.
template <typename Type, etl::size_t Size>
span(etl::array<Type, Size>&) -> span<Type, Size>;

// Deduction Guides. From etl::array<Type const, Size>.
template <typename Type, etl::size_t Size>
span(etl::array<Type, Size> const&) -> span<Type const, Size>;

// Deduction Guides. From Container.
template <typename Container,
    typename Element
    = etl::remove_pointer_t<decltype(etl::declval<Container&>().data())>>
span(Container&) -> span<Element>;

// Deduction Guides. From Container const.
template <typename Container,
    typename Element
    = etl::remove_pointer_t<decltype(etl::declval<Container const&>().data())>>
span(Container const&) -> span<Element>;

} // namespace etl

#endif // TETL_SPAN_SPAN_HPP