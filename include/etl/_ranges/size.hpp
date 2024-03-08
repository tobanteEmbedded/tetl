// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RANGES_SIZE_HPP
#define TETL_RANGES_SIZE_HPP

#include <etl/_array/c_array.hpp>
#include <etl/_concepts/integral.hpp>
#include <etl/_ranges/decay_copy.hpp>
#include <etl/_ranges/disable_sized_range.hpp>
#include <etl/_ranges/iterator_t.hpp>
#include <etl/_type_traits/remove_cv.hpp>

namespace etl::ranges {

namespace _size {

auto size(auto&) -> void       = delete;
auto size(auto const&) -> void = delete;

// clang-format off
template <typename T>
concept has_member_size = not etl::ranges::disable_sized_range<etl::remove_cv_t<T>> and requires(T&& t) {
    { decay_copy(t.size()) } -> etl::integral;
};

template <typename T>
concept has_adl_size = not has_member_size<T> and not etl::ranges::disable_sized_range<etl::remove_cv_t<T>> and requires(T&& t) {
    { decay_copy(size(t)) } -> etl::integral;
};

// clang-format on

struct fn {
    template <typename T, etl::size_t Size>
    [[nodiscard]] constexpr auto operator()(etl::c_array<T, Size>& /*t*/) const noexcept
    {
        return Size;
    }

    template <typename T, etl::size_t Size>
    [[nodiscard]] constexpr auto operator()(etl::c_array<T, Size>&& /*t*/) const noexcept
    {
        return Size;
    }

    template <has_member_size T>
    [[nodiscard]] constexpr auto operator()(T&& t) const noexcept(noexcept(decay_copy(t.size())))
    {
        return decay_copy(t.size());
    }

    template <has_adl_size T>
    [[nodiscard]] constexpr auto operator()(T&& t) const noexcept(noexcept(decay_copy(size(t))))
    {
        return decay_copy(size(t));
    }

    auto operator()(auto&&) const -> void = delete;
};

} // namespace _size

inline namespace _cpo {
inline constexpr auto size = _size::fn {};
} // namespace _cpo

} // namespace etl::ranges

#endif // TETL_RANGES_SIZE_HPP
