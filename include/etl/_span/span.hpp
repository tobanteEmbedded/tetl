// SPDX-License-Identifier: BSL-1.0
// SPDX-FileCopyrightText: Copyright (C) 2020 Tobias Hienzsch

#ifndef TETL_SPAN_SPAN_HPP
#define TETL_SPAN_SPAN_HPP

#include <etl/_config/all.hpp>

#include <etl/_array/array.hpp>
#include <etl/_array/c_array.hpp>
#include <etl/_contracts/check.hpp>
#include <etl/_cstddef/byte.hpp>
#include <etl/_iterator/begin.hpp>
#include <etl/_iterator/data.hpp>
#include <etl/_iterator/end.hpp>
#include <etl/_iterator/iter_reference_t.hpp>
#include <etl/_iterator/next.hpp>
#include <etl/_iterator/rbegin.hpp>
#include <etl/_iterator/rend.hpp>
#include <etl/_iterator/reverse_iterator.hpp>
#include <etl/_iterator/size.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_ranges/borrowed_range.hpp>
#include <etl/_ranges/enable_borrowed_range.hpp>
#include <etl/_ranges/range_reference_t.hpp>
#include <etl/_ranges/size.hpp>
#include <etl/_ranges/sized_range.hpp>
#include <etl/_span/dynamic_extent.hpp>
#include <etl/_type_traits/conditional.hpp>
#include <etl/_type_traits/declval.hpp>
#include <etl/_type_traits/is_array.hpp>
#include <etl/_type_traits/is_const.hpp>
#include <etl/_type_traits/is_convertible.hpp>
#include <etl/_type_traits/remove_cvref.hpp>
#include <etl/_type_traits/remove_pointer.hpp>
#include <etl/_type_traits/remove_reference.hpp>
#include <etl/_type_traits/type_identity.hpp>

namespace etl {

/// A non-owning view over a contiguous sequence of objects.
///
/// The class template span describes an object that can refer to a
/// contiguous sequence of objects with the first element of the sequence at
/// position zero. A span can either have a static extent, in which case the
/// number of elements in the sequence is known and encoded in the type, or a
/// dynamic extent.
///
/// If a span has dynamic extent a typical implementation holds
/// two members: a pointer to T and a size. A span with static extent may have
/// only one member: a pointer to T.
///
/// \ingroup span
/// \headerfile etl/span.hpp
template <typename T, size_t Extent = etl::dynamic_extent>
struct span;

namespace detail {

template <typename T>
inline constexpr auto is_span = false;

template <typename T, size_t Size>
inline constexpr auto is_span<etl::span<T, Size>> = true;

template <typename From, typename To>
concept span_convertible_from = is_convertible_v<From (*)[], To (*)[]>;

template <size_t Offset, size_t Count, size_t Extent>
[[nodiscard]] consteval auto subspan_extent() -> size_t
{
    if (Count != dynamic_extent) {
        return Count;
    }
    if (Extent != dynamic_extent) {
        return Extent - Offset;
    }
    return dynamic_extent;
}

} // namespace detail

template <typename T, size_t Extent>
struct span {
    using element_type     = T;
    using value_type       = etl::remove_cv_t<T>;
    using size_type        = etl::size_t;
    using difference_type  = etl::ptrdiff_t;
    using pointer          = T*;
    using const_pointer    = T const*;
    using reference        = T&;
    using const_reference  = T const&;
    using iterator         = T*;
    using reverse_iterator = etl::reverse_iterator<iterator>;

    /// \brief The number of elements in the sequence, or etl::dynamic_extent
    /// if dynamic.
    static constexpr size_type extent = Extent;

    /// \brief Constructs a span. Constructs an empty span whose
    /// data() == nullptr and size() == 0.
    ///
    /// \details This overload only participates in overload resolution
    /// if extent == 0 || extent == etl::dynamic_extent.
    constexpr span() noexcept
        requires(extent == 0 or extent == dynamic_extent)
    = default;

    /// \brief Constructs a span.
    /// \details Constructs a span that is a view over the range [first, first + count);
    template <typename /*contiguous_iterator*/ It>
        requires detail::span_convertible_from<remove_reference_t<iter_reference_t<It>>, T>
    explicit(extent != dynamic_extent) constexpr span(It first, size_type count)
        : _storage{first, count}
    {
    }

    /// Constructs a span. From a c style array.
    template <size_t N>
        requires(extent == dynamic_extent or extent == N)
    constexpr span(c_array<type_identity_t<T>, N>& arr) noexcept
        : _storage{&arr[0], N}
    {
    }

    /// Constructs a span. From a array<Type,Size>.
    template <detail::span_convertible_from<T> U, size_t N>
        requires(extent == dynamic_extent or extent == N)
    constexpr span(array<U, N>& arr) noexcept
        : _storage{arr.data(), arr.size()}
    {
    }

    /// Constructs a span. From a array<Type,Size> const.
    template <detail::span_convertible_from<T> U, size_t N>
        requires(extent == dynamic_extent or extent == N)
    constexpr span(array<U, N> const& arr) noexcept
        : _storage{arr.data(), arr.size()}
    {
    }

    /// Constructs a span.
    template <typename /*etl::ranges::contiguous_range*/ R>
        requires(
            ranges::sized_range<R>
            and (ranges::borrowed_range<R> or is_const_v<T>)
            and not is_array_v<remove_cvref_t<R>>
            and not is_etl_array<R>
            and not detail::is_span<R>
            and detail::span_convertible_from<remove_reference_t<ranges::range_reference_t<R>>, T>
        )
    explicit(extent != dynamic_extent) constexpr span(R&& r)
        : _storage{r.data(), ranges::size(r)}
    {
    }

    template <detail::span_convertible_from<T> U, size_t N>
        requires(extent == dynamic_extent or N == dynamic_extent or N == extent)
    explicit(extent != dynamic_extent and N == dynamic_extent) constexpr span(span<U, N> const& source) noexcept
        : _storage{source.data(), source.size()}
    {
    }

    /// \brief Constructs a span.
    constexpr span(span const& other) noexcept = default;

    /// \brief Returns an iterator to the first element of the span. If the span
    /// is empty, the returned iterator will be equal to end().
    [[nodiscard]] constexpr auto begin() const noexcept -> iterator
    {
        return _storage.data();
    }

    /// \brief Returns an iterator to the element following the last element of
    /// the span. This element acts as a placeholder; attempting to access it
    /// results in undefined behavior
    [[nodiscard]] constexpr auto end() const noexcept -> iterator
    {
        return begin() + size();
    }

    /// \brief Returns a reverse iterator to the first element of the reversed
    /// span. It corresponds to the last element of the non-reversed span. If
    /// the span is empty, the returned iterator is equal to rend().
    [[nodiscard]] constexpr auto rbegin() const noexcept -> reverse_iterator
    {
        return reverse_iterator(end());
    }

    /// \brief Returns a reverse iterator to the element following the last
    /// element of the reversed span. It corresponds to the element preceding
    /// the first element of the non-reversed span. This element acts as a
    /// placeholder, attempting to access it results in undefined behavior.
    [[nodiscard]] constexpr auto rend() const noexcept -> reverse_iterator
    {
        return reverse_iterator(begin());
    }

    /// \brief Returns a reference to the first element in the span. Calling
    /// front on an empty span results in undefined behavior.
    [[nodiscard]] constexpr auto front() const -> reference
    {
        TETL_PRECONDITION(not empty());
        return *begin();
    }

    /// \brief Returns a reference to the last element in the span. Calling
    /// front on an empty span results in undefined behavior.
    [[nodiscard]] constexpr auto back() const -> reference
    {
        TETL_PRECONDITION(not empty());
        return *(end() - 1);
    }

    /// \brief Returns a reference to the idx-th element of the sequence. The
    /// behavior is undefined if idx is out of range (i.e., if it is greater
    /// than or equal to size()).
    [[nodiscard]] constexpr auto operator[](size_type idx) const -> reference
    {
        TETL_PRECONDITION(idx < size());
        return data()[idx];
    }

    /// \brief Returns a pointer to the beginning of the sequence.
    [[nodiscard]] constexpr auto data() const noexcept -> pointer
    {
        return _storage.data();
    }

    /// \brief Returns the number of elements in the span.
    [[nodiscard]] constexpr auto size() const noexcept -> size_type
    {
        return _storage.size();
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

    /// \brief Obtains a span that is a view over the first Count elements of
    /// this span. The program is ill-formed if Count > Extent.
    template <size_t Count>
    [[nodiscard]] constexpr auto first() const -> span<element_type, Count>
    {
        static_assert(Count <= Extent);
        return span<element_type, Count>{data(), static_cast<size_type>(Count)};
    }

    /// \brief Obtains a span that is a view over the first Count elements of
    /// this span. The behavior is undefined if Count > size().
    [[nodiscard]] constexpr auto first(size_type count) const -> span<element_type, dynamic_extent>
    {
        TETL_PRECONDITION(count <= size());
        return {data(), static_cast<size_type>(count)};
    }

    /// \brief Obtains a span that is a view over the last Count elements of
    /// this span. The program is ill-formed if Count > Extent.
    template <size_t Count>
    [[nodiscard]] constexpr auto last() const -> span<element_type, Count>
    {
        static_assert(Count <= Extent);
        return span<element_type, Count>{data() + (size() - Count), static_cast<size_type>(Count)};
    }

    /// \brief Obtains a span that is a view over the last Count elements of
    /// this span. The behavior is undefined if Count > size().
    [[nodiscard]] constexpr auto last(size_type count) const -> span<element_type, dynamic_extent>
    {
        TETL_PRECONDITION(count <= size());
        return {data() + (size() - count), static_cast<size_type>(count)};
    }

    /// \brief Obtains a span that is a view over the Count elements of this
    /// span starting at offset Offset. If Count is etl::dynamic_extent, the
    /// number of elements in the subspan is size() - offset (i.e., it ends at
    /// the end of *this.).
    template <size_t Offset, size_t Count = dynamic_extent>
    [[nodiscard]] constexpr auto subspan() const -> span<T, detail::subspan_extent<Offset, Count, Extent>()>
    {
        static_assert(Offset <= Extent);
        static_assert(Count == dynamic_extent or Count <= Extent - Offset);

        auto const ptr = data() + Offset;
        auto const sz  = static_cast<size_type>(Count == dynamic_extent ? size() - Offset : Count);
        return span<T, detail::subspan_extent<Offset, Count, Extent>()>{ptr, sz};
    }

    /// \brief Obtains a span that is a view over the Count elements of this
    /// span starting at offset Offset. If Count is etl::dynamic_extent, the
    /// number of elements in the subspan is size() - offset (i.e., it ends at
    /// the end of *this.).
    [[nodiscard]] constexpr auto subspan(size_type offset, size_type count = dynamic_extent) const
        -> span<T, dynamic_extent>
    {
        TETL_PRECONDITION(offset <= size());
        TETL_PRECONDITION(count != dynamic_extent ? (count <= size() - offset) : true);
        auto const sz = count == dynamic_extent ? size() - offset : count;
        return {data() + offset, static_cast<size_type>(sz)};
    }

private:
    struct static_storage {
        constexpr static_storage() = default;
        constexpr static_storage(T* ptr, size_type /*sz*/) noexcept
            : _data{ptr}
        {
        }

        [[nodiscard]] constexpr auto data() const noexcept
        {
            return _data;
        }
        [[nodiscard]] constexpr auto size() const noexcept
        {
            return Extent;
        }

    private:
        T* _data{nullptr};
    };

    struct dynamic_storage {
        constexpr dynamic_storage() = default;
        constexpr dynamic_storage(T* ptr, size_type sz) noexcept
            : _data{ptr}
            , _size{sz}
        {
        }

        [[nodiscard]] constexpr auto data() const noexcept
        {
            return _data;
        }
        [[nodiscard]] constexpr auto size() const noexcept
        {
            return _size;
        }

    private:
        T* _data{nullptr};
        etl::size_t _size{0};
    };

    using storage = conditional_t<Extent == dynamic_extent, dynamic_storage, static_storage>;
    storage _storage;
};

// Deduction Guides. From raw array.
template <typename Type, size_t Extent>
span(c_array<Type, Extent>&) -> span<Type, Extent>;

// Deduction Guides. From array<Type, Size>.
template <typename Type, size_t Size>
span(array<Type, Size>&) -> span<Type, Size>;

// Deduction Guides. From array<Type const, Size>.
template <typename Type, size_t Size>
span(array<Type, Size> const&) -> span<Type const, Size>;

// Deduction Guides. From a contiguous range
template <ranges::range /*ranges::contiguous_range*/ R>
span(R&&) -> span<remove_reference_t<ranges::range_reference_t<R>>>;

namespace ranges {
template <typename T, etl::size_t Extent>
inline constexpr bool enable_borrowed_range<etl::span<T, Extent>> = true;
} // namespace ranges

namespace detail {
template <typename T, etl::size_t N>
inline constexpr etl::size_t span_as_bytes_size = N == etl::dynamic_extent ? etl::dynamic_extent : sizeof(T) * N;
} // namespace detail

/// Obtains a view to the object representation of the elements of the
/// span s.
///
/// If N is dynamic_extent, the extent of the returned span S is also
/// dynamic_extent; otherwise it is sizeof(T) * N.
/// \relates span
/// \ingroup span
template <typename T, size_t N>
[[nodiscard]] auto as_bytes(span<T, N> s) noexcept -> span<byte const, detail::span_as_bytes_size<T, N>>
{
    return {reinterpret_cast<byte const*>(s.data()), s.size_bytes()};
}

/// Obtains a view to the object representation of the elements of the
/// span s.
///
/// If N is dynamic_extent, the extent of the returned span S is also
/// dynamic_extent; otherwise it is sizeof(T) * N. Only participates in overload
/// resolution if is_const_v<T> is false.
/// \relates span
/// \ingroup span
template <typename T, size_t N>
    requires(not is_const_v<T>)
[[nodiscard]] auto as_writable_bytes(span<T, N> s) noexcept -> span<byte, detail::span_as_bytes_size<T, N>>
{
    return {reinterpret_cast<byte*>(s.data()), s.size_bytes()};
}

} // namespace etl

#endif // TETL_SPAN_SPAN_HPP
