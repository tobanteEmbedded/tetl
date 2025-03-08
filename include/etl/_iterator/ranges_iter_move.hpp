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
concept adl_iter_move = (is_class_v<remove_cvref_t<T>> or is_enum_v<remove_cvref_t<T>>)
                    and requires(T&& t) { iter_move(etl::forward<T>(t)); };

template <typename T>
concept can_move = not adl_iter_move<T> and requires(T&& t) {
    *t;
    requires is_lvalue_reference_v<decltype(*t)>;
};

template <typename T>
concept can_deref = not adl_iter_move<T> and !can_move<T> and requires(T&& t) {
    *t;
    requires(!is_lvalue_reference_v<decltype(*t)>);
};

struct fn {
    template <adl_iter_move Iter>
    [[nodiscard]] constexpr auto operator()(Iter&& i) const noexcept(noexcept(iter_move(etl::forward<Iter>(i))))
        -> decltype(auto)
    {
        return iter_move(etl::forward<Iter>(i));
    }

    template <can_move Iter>
    [[nodiscard]] constexpr auto operator()(Iter&& i) const noexcept(noexcept(etl::move(*etl::forward<Iter>(i))))
        -> decltype(etl::move(*etl::forward<Iter>(i)))
    {
        return etl::move(*etl::forward<Iter>(i));
    }

    template <can_deref Iter>
    [[nodiscard]] constexpr auto operator()(Iter&& i) const noexcept(noexcept(*etl::forward<Iter>(i)))
        -> decltype(*etl::forward<Iter>(i))
    {
        return *etl::forward<Iter>(i);
    }
};

} // namespace iter_move_cpo

inline namespace cpo {
/// \ingroup iterator
inline constexpr auto iter_move = iter_move_cpo::fn{};
} // namespace cpo

} // namespace etl::ranges

#endif // TETL_ITERATOR_RANGES_ITER_MOVE_HPP
