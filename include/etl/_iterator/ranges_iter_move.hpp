// SPDX-License-Identifier: BSL-1.0

#ifndef TETL_ITERATOR_RANGES_ITER_MOVE_HPP
#define TETL_ITERATOR_RANGES_ITER_MOVE_HPP

#include <etl/_type_traits/is_class.hpp>
#include <etl/_type_traits/is_enum.hpp>
#include <etl/_type_traits/is_lvalue_reference.hpp>
#include <etl/_type_traits/remove_cvref.hpp>
#include <etl/_utility/forward.hpp>
#include <etl/_utility/move.hpp>

namespace etl::ranges {

namespace iter_move_cpo {

auto iter_move() -> void = delete;

template <typename T>
concept adl_iter_move = (etl::is_class_v<etl::remove_cvref_t<T>> or etl::is_enum_v<etl::remove_cvref_t<T>>)
                    and requires(T&& t) { iter_move(TETL_FORWARD(t)); };

template <typename T>
concept can_move = not adl_iter_move<T> and requires(T&& t) {
    *t;
    requires etl::is_lvalue_reference_v<decltype(*t)>;
};

template <typename T>
concept can_deref = not adl_iter_move<T> and !can_move<T> and requires(T&& t) {
    *t;
    requires(!etl::is_lvalue_reference_v<decltype(*t)>);
};

struct fn {
    template <adl_iter_move Iter>
    [[nodiscard]] constexpr auto operator()(Iter&& i) const
        noexcept(noexcept(iter_move(TETL_FORWARD(i)))) -> decltype(auto)
    {
        return iter_move(TETL_FORWARD(i));
    }

    template <can_move Iter>
    [[nodiscard]] constexpr auto operator()(Iter&& i) const
        noexcept(noexcept(TETL_MOVE(*TETL_FORWARD(i)))) -> decltype(TETL_MOVE(*TETL_FORWARD(i)))
    {
        return TETL_MOVE(*TETL_FORWARD(i));
    }

    template <can_deref Iter>
    [[nodiscard]] constexpr auto operator()(Iter&& i) const
        noexcept(noexcept(*TETL_FORWARD(i))) -> decltype(*TETL_FORWARD(i))
    {
        return *TETL_FORWARD(i);
    }
};

} // namespace iter_move_cpo

inline namespace cpo {
inline constexpr auto iter_move = iter_move_cpo::fn{};
} // namespace cpo

} // namespace etl::ranges

#endif // TETL_ITERATOR_RANGES_ITER_MOVE_HPP
