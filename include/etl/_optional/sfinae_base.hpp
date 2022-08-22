/// \copyright Tobias Hienzsch 2019-2021
/// Distributed under the Boost Software License, Version 1.0.
/// See accompanying file LICENSE or copy at http://boost.org/LICENSE_1_0.txt

#ifndef TETL_OPTIONAL_SFINAE_BASE_HPP
#define TETL_OPTIONAL_SFINAE_BASE_HPP

namespace etl::detail {
template <bool CanCopy, bool CanMove>
struct sfinae_ctor_base {
};
template <>
struct sfinae_ctor_base<false, false> {
    sfinae_ctor_base()                                           = default;
    sfinae_ctor_base(sfinae_ctor_base const&)                    = delete;
    sfinae_ctor_base(sfinae_ctor_base&&)                         = delete;
    auto operator=(sfinae_ctor_base const&) -> sfinae_ctor_base& = default;
    auto operator=(sfinae_ctor_base&&) -> sfinae_ctor_base&      = default;
};
template <>
struct sfinae_ctor_base<true, false> {
    sfinae_ctor_base()                                           = default;
    sfinae_ctor_base(sfinae_ctor_base const&)                    = default;
    sfinae_ctor_base(sfinae_ctor_base&&)                         = delete;
    auto operator=(sfinae_ctor_base const&) -> sfinae_ctor_base& = default;
    auto operator=(sfinae_ctor_base&&) -> sfinae_ctor_base&      = default;
};
template <>
struct sfinae_ctor_base<false, true> {
    sfinae_ctor_base()                                           = default;
    sfinae_ctor_base(sfinae_ctor_base const&)                    = delete;
    sfinae_ctor_base(sfinae_ctor_base&&)                         = default;
    auto operator=(sfinae_ctor_base const&) -> sfinae_ctor_base& = default;
    auto operator=(sfinae_ctor_base&&) -> sfinae_ctor_base&      = default;
};

template <bool CanCopy, bool CanMove>
struct sfinae_assign_base {
};
template <>
struct sfinae_assign_base<false, false> {
    sfinae_assign_base()                                             = default;
    sfinae_assign_base(sfinae_assign_base const&)                    = default;
    sfinae_assign_base(sfinae_assign_base&&)                         = default;
    auto operator=(sfinae_assign_base const&) -> sfinae_assign_base& = delete;
    auto operator=(sfinae_assign_base&&) -> sfinae_assign_base&      = delete;
};
template <>
struct sfinae_assign_base<true, false> {
    sfinae_assign_base()                                             = default;
    sfinae_assign_base(sfinae_assign_base const&)                    = default;
    sfinae_assign_base(sfinae_assign_base&&)                         = default;
    auto operator=(sfinae_assign_base const&) -> sfinae_assign_base& = default;
    auto operator=(sfinae_assign_base&&) -> sfinae_assign_base&      = delete;
};
template <>
struct sfinae_assign_base<false, true> {
    sfinae_assign_base()                                             = default;
    sfinae_assign_base(sfinae_assign_base const&)                    = default;
    sfinae_assign_base(sfinae_assign_base&&)                         = default;
    auto operator=(sfinae_assign_base const&) -> sfinae_assign_base& = delete;
    auto operator=(sfinae_assign_base&&) -> sfinae_assign_base&      = default;
};

} // namespace etl::detail

#endif // TETL_OPTIONAL_SFINAE_BASE_HPP
