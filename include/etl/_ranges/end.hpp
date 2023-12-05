// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_RANGES_END_HPP
#define TETL_RANGES_END_HPP

#include <etl/_iterator/input_or_output_iterator.hpp>
#include <etl/_iterator/sentinel_for.hpp>
#include <etl/_ranges/can_borrow.hpp>
#include <etl/_ranges/decay_copy.hpp>
#include <etl/_ranges/iterator_t.hpp>

namespace etl::ranges {

namespace adl_checks {

auto end(auto&) -> void       = delete;
auto end(auto const&) -> void = delete;

// clang-format off
template <typename T>
concept has_member_end = ranges::detail::can_borrow<T> and requires(T&& t) {
    { decay_copy(t.end()) } -> etl::sentinel_for<etl::ranges::iterator_t<T>>;
};

template <typename T>
concept has_adl_end = not has_member_end<T> and ranges::detail::can_borrow<T> and requires(T&& t) {
    { decay_copy(end(t)) } -> etl::sentinel_for<etl::ranges::iterator_t<T>>;
};
// clang-format on

} // namespace adl_checks

struct end_fn {
    template <typename T, etl::size_t Size>
        requires(sizeof(T) >= 0) // NOLINT(bugprone-sizeof-expression)
    [[nodiscard]] constexpr auto operator()(T (&t)[Size]) const noexcept
    {
        return t + Size;
    }

    template <typename T>
        requires adl_checks::has_member_end<T>
    [[nodiscard]] constexpr auto operator()(T&& t) const noexcept(noexcept(decay_copy(t.end())))
    {
        return decay_copy(t.end());
    }

    template <typename T>
        requires adl_checks::has_adl_end<T>
    [[nodiscard]] constexpr auto operator()(T&& t) const noexcept(noexcept(decay_copy(end(t))))
    {
        return decay_copy(end(t));
    }

    auto operator()(auto&&) const -> void = delete;
};

inline constexpr auto end = end_fn {};

} // namespace etl::ranges

#endif // TETL_RANGES_END_HPP
