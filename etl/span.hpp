/*
Copyright (c) 2019-2020, Tobias Hienzsch
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice,
   this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
DAMAGE.
*/

#ifndef TAETL_SPAN_HPP
#define TAETL_SPAN_HPP

#include "etl/array.hpp"
#include "etl/limits.hpp"
#include "etl/type_traits.hpp"

namespace etl
{
/**
 * @brief etl::dynamic_extent is a constant of type etl::size_t that is used to
 * differentiate etl::span of static and dynamic extent.
 */
inline constexpr auto dynamic_extent = size_t(-1);

/**
 * @brief A non-owning view over a contiguous sequence of objects.
 *
 * @details The class template span describes an object that can refer to a
 * contiguous sequence of objects with the first element of the sequence at
 * position zero. A span can either have a static extent, in which case the
 * number of elements in the sequence is known and encoded in the type, or a
 * dynamic extent.
 *
 * If a span has dynamic extent a typical implementation holds
 * two members: a pointer to T and a size. A span with static extent may have
 * only one member: a pointer to T.
 */
template <class ElementType, size_t Extent = etl::dynamic_extent>
class span
{
public:
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

    /**
     * @brief The number of elements in the sequence, or etl::dynamic_extent
     * if dynamic.
     */
    static constexpr size_type extent = Extent;

    /**
     * @brief Constructs a span. Constructs an empty span whose
     * data() == nullptr and size() == 0.
     *
     * @details This overload only participates in overload resolution
     * if extent == 0 || extent == etl::dynamic_extent.
     *
     * @todo Remove from overload with concepts once available.
     */
    constexpr span() noexcept = default;

    // /**
    //  * @brief Constructs a span.
    //  */
    // template <class It>
    // explicit(extent != etl::dynamic_extent) constexpr span(It first,
    //                                                        size_type count);

    // /**
    //  * @brief Constructs a span.
    //  */
    // template <class It, class End>
    // explicit(extent != etl::dynamic_extent) constexpr span(It first, End
    // last);

    // /**
    //  * @brief Constructs a span.
    //  */
    // template <etl::size_t N>
    // constexpr span(element_type (&arr)[N]) noexcept;

    // /**
    //  * @brief Constructs a span.
    //  */
    // template <class U, etl::size_t N>
    // constexpr span(etl::array<U, N>& arr) noexcept;

    // /**
    //  * @brief Constructs a span.
    //  */
    // template <class U, etl::size_t N>
    // constexpr span(const etl::array<U, N>& arr) noexcept;

    // /**
    //  * @brief Constructs a span.
    //  */
    // template <class R>
    // explicit(extent != etl::dynamic_extent) constexpr span(R&& r);

    // /**
    //  * @brief Constructs a span.
    //  */
    // template <class U, etl::size_t N>
    // explicit(extent != etl::dynamic_extent
    //          && N == etl::dynamic_extent) constexpr span(const etl::span<U,
    //          N>&
    //                                                          s) noexcept;

    /**
     * @brief Constructs a span.
     */
    constexpr span(const span& other) noexcept = default;

    /**
     * @brief Returns a pointer to the beginning of the sequence.
     */
    [[nodiscard]] constexpr auto data() const noexcept -> pointer { return data_; }

    /**
     * @brief Returns the number of elements in the span.
     */
    [[nodiscard]] constexpr auto size() const noexcept -> size_type { return size_; }

private:
    ElementType* data_ = nullptr;
    size_type size_    = 0;
};
}  // namespace etl

#endif  // TAETL_SPAN_HPP