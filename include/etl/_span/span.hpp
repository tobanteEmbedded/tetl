// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_SPAN_SPAN_HPP
#define TETL_SPAN_SPAN_HPP

#include <etl/_config/all.hpp>

#include <etl/_array/array.hpp>
#include <etl/_iterator/begin.hpp>
#include <etl/_iterator/data.hpp>
#include <etl/_iterator/end.hpp>
#include <etl/_iterator/next.hpp>
#include <etl/_iterator/rbegin.hpp>
#include <etl/_iterator/rend.hpp>
#include <etl/_iterator/reverse_iterator.hpp>
#include <etl/_iterator/size.hpp>
#include <etl/_limits/numeric_limits.hpp>
#include <etl/_span/dynamic_extent.hpp>
#include <etl/_type_traits/declval.hpp>
#include <etl/_type_traits/remove_pointer.hpp>

namespace etl {

namespace detail {
template <size_t Offset, size_t Count, size_t Extent>
[[nodiscard]] TETL_CONSTEVAL auto subspan_extent() -> size_t
{
    if (Count != dynamic_extent) { return Count; }
    if (Extent != dynamic_extent) { return Extent - Offset; }
    return dynamic_extent;
}
} // namespace detail

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
template <typename ElementType, size_t Extent = etl::dynamic_extent>
struct span {
    using element_type     = ElementType;
    using value_type       = etl::remove_cv_t<ElementType>;
    using size_type        = etl::size_t;
    using difference_type  = etl::ptrdiff_t;
    using pointer          = ElementType*;
    using const_pointer    = ElementType const*;
    using reference        = ElementType&;
    using const_reference  = ElementType const&;
    using iterator         = ElementType*;
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
    template <typename It>
    explicit(extent != dynamic_extent) constexpr span(It first, size_type count) : _data {first}, _size {count}
    {
    }

    // /// \brief Constructs a span.
    // template <typename It, typename End>
    // explicit(extent != etl::dynamic_extent) constexpr span(It first, End last);

    /// \brief Constructs a span. From a c style array.
    template <size_t N>
    constexpr span(element_type (&arr)[N]) noexcept : _data {&arr[0]}, _size {N}
    {
    }

    /// \brief Constructs a span. From a array<Type,Size>.
    template <typename U, size_t N>
    constexpr span(array<U, N>& arr) noexcept : _data {arr.data()}, _size {arr.size()}
    {
    }

    /// \brief Constructs a span. From a array<Type,Size> const.
    template <typename U, size_t N>
    constexpr span(array<U, N> const& arr) noexcept : _data {arr.data()}, _size {arr.size()}
    {
    }

    /// \brief Constructs a span.
    template <typename R>
    explicit(extent != dynamic_extent) constexpr span(R&& r) : _data {r.data()}, _size {r.size()}
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
    [[nodiscard]] constexpr auto begin() const noexcept -> iterator { return &_data[0]; }

    /// \brief Returns an iterator to the element following the last element of
    /// the span. This element acts as a placeholder; attempting to access it
    /// results in undefined behavior
    [[nodiscard]] constexpr auto end() const noexcept -> iterator { return begin() + size(); }

    /// \brief Returns a reverse iterator to the first element of the reversed
    /// span. It corresponds to the last element of the non-reversed span. If
    /// the span is empty, the returned iterator is equal to rend().
    [[nodiscard]] auto rbegin() const noexcept -> reverse_iterator { return reverse_iterator(end()); }

    /// \brief Returns a reverse iterator to the element following the last
    /// element of the reversed span. It corresponds to the element preceding
    /// the first element of the non-reversed span. This element acts as a
    /// placeholder, attempting to access it results in undefined behavior.
    [[nodiscard]] auto rend() const noexcept -> reverse_iterator { return reverse_iterator(begin()); }

    /// \brief Returns a reference to the first element in the span. Calling
    /// front on an empty span results in undefined behavior.
    [[nodiscard]] constexpr auto front() const -> reference { return *begin(); }

    /// \brief Returns a reference to the last element in the span. Calling
    /// front on an empty span results in undefined behavior.
    [[nodiscard]] constexpr auto back() const -> reference { return *(end() - 1); }

    /// \brief Returns a reference to the idx-th element of the sequence. The
    /// behavior is undefined if idx is out of range (i.e., if it is greater
    /// than or equal to size()).
    [[nodiscard]] constexpr auto operator[](size_type idx) const -> reference { return data()[idx]; }

    /// \brief Returns a pointer to the beginning of the sequence.
    [[nodiscard]] constexpr auto data() const noexcept -> pointer { return _data; }

    /// \brief Returns the number of elements in the span.
    [[nodiscard]] constexpr auto size() const noexcept -> size_type { return _size; }

    /// \brief Returns the number of elements in the span.
    [[nodiscard]] constexpr auto size_bytes() const noexcept -> size_type { return size() * sizeof(element_type); }

    /// \brief Checks if the span is empty.
    [[nodiscard]] constexpr auto empty() const noexcept -> bool { return size() == 0; }

    /// \brief Obtains a span that is a view over the first Count elements of
    /// this span. The program is ill-formed if Count > Extent.
    template <size_t Count>
    [[nodiscard]] constexpr auto first() const -> span<element_type, Count>
    {
        static_assert(!(Count > Extent));
        return span<element_type, Count> {data(), static_cast<size_type>(Count)};
    }

    /// \brief Obtains a span that is a view over the first Count elements of
    /// this span. The behavior is undefined if Count > size().
    [[nodiscard]] constexpr auto first(size_type count) const -> span<element_type, dynamic_extent>
    {
        TETL_ASSERT(!(count > size()));
        return {data(), static_cast<size_type>(count)};
    }

    /// \brief Obtains a span that is a view over the last Count elements of
    /// this span. The program is ill-formed if Count > Extent.
    template <size_t Count>
    [[nodiscard]] constexpr auto last() const -> span<element_type, Count>
    {
        static_assert(!(Count > Extent));
        return span<element_type, Count> {data() + (size() - Count), static_cast<size_type>(Count)};
    }

    /// \brief Obtains a span that is a view over the last Count elements of
    /// this span. The behavior is undefined if Count > size().
    [[nodiscard]] constexpr auto last(size_type count) const -> span<element_type, dynamic_extent>
    {
        TETL_ASSERT(!(count > size()));
        return {data() + (size() - count), static_cast<size_type>(count)};
    }

    /// \brief Obtains a span that is a view over the Count elements of this
    /// span starting at offset Offset. If Count is etl::dynamic_extent, the
    /// number of elements in the subspan is size() - offset (i.e., it ends at
    /// the end of *this.).
    template <size_t Offset, size_t Count = dynamic_extent>
    [[nodiscard]] constexpr auto subspan() const -> span<element_type, detail::subspan_extent<Offset, Count, Extent>()>
    {
        static_assert(!(Offset > Extent));
        static_assert(!(Count == dynamic_extent || Count <= Extent - Offset)); // NOLINT(*-simplify-boolean-expr)
        auto const sz = Count == dynamic_extent ? size() - Offset : Count;
        return {data() + Offset, static_cast<size_type>(sz)};
    }

    /// \brief Obtains a span that is a view over the Count elements of this
    /// span starting at offset Offset. If Count is etl::dynamic_extent, the
    /// number of elements in the subspan is size() - offset (i.e., it ends at
    /// the end of *this.).
    [[nodiscard]] constexpr auto subspan(
        size_type offset, size_type count = dynamic_extent) const -> span<element_type, dynamic_extent>
    {
        TETL_ASSERT(!(offset > size()));
        TETL_ASSERT(!(count != dynamic_extent && count > size() - offset));
        auto const sz = count == dynamic_extent ? size() - offset : count;
        return {data() + offset, static_cast<size_type>(sz)};
    }

private:
    pointer _data   = nullptr;
    size_type _size = 0;
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
template <typename Container, typename Element = etl::remove_pointer_t<decltype(etl::declval<Container&>().data())>>
span(Container&) -> span<Element>;

// Deduction Guides. From Container const.
template <typename Container,
    typename Element = etl::remove_pointer_t<decltype(etl::declval<Container const&>().data())>>
span(Container const&) -> span<Element>;

} // namespace etl

#endif // TETL_SPAN_SPAN_HPP
