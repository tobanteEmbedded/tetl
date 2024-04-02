// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RANGES_BEGIN_HPP
#define TETL_RANGES_BEGIN_HPP

#include <etl/_iterator/input_or_output_iterator.hpp>
#include <etl/_ranges/can_borrow.hpp>
#include <etl/_ranges/decay_copy.hpp>

namespace etl::ranges {

namespace begin_cpo {

auto begin(auto&) -> void       = delete;
auto begin(auto const&) -> void = delete;

// clang-format off
template <typename T>
concept has_member_begin = ranges::detail::can_borrow<T> and requires(T&& t) {
    { decay_copy(t.begin()) } -> input_or_output_iterator;
};

template <typename T>
concept has_adl_begin = not has_member_begin<T> and ranges::detail::can_borrow<T> and requires(T&& t) {
    { decay_copy(begin(t)) } -> input_or_output_iterator;
};
// clang-format on

struct fn {
    template <typename T>
        requires(sizeof(T) >= 0) // NOLINT(bugprone-sizeof-expression)
    [[nodiscard]] constexpr auto operator()(T (&t)[]) const noexcept
    {
        return t + 0;
    }

    template <typename T, etl::size_t Size>
        requires(sizeof(T) >= 0) // NOLINT(bugprone-sizeof-expression)
    [[nodiscard]] constexpr auto operator()(T (&t)[Size]) const noexcept
    {
        return t + 0;
    }

    template <has_member_begin T>
    [[nodiscard]] constexpr auto operator()(T&& t) const noexcept(noexcept(decay_copy(t.begin())))
    {
        return decay_copy(t.begin());
    }

    template <has_adl_begin T>
    [[nodiscard]] constexpr auto operator()(T&& t) const noexcept(noexcept(decay_copy(begin(t))))
    {
        return decay_copy(begin(t));
    }

    auto operator()(auto&&) const -> void = delete;
};

} // namespace begin_cpo

inline namespace cpo {
/// \ingroup ranges
inline constexpr auto begin = begin_cpo::fn{};
} // namespace cpo

} // namespace etl::ranges

#endif // TETL_RANGES_BEGIN_HPP
