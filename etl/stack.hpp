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

#ifndef TAETL_STACK_HPP
#define TAETL_STACK_HPP

#include "etl/iterator.hpp"
#include "etl/type_traits.hpp"

namespace etl
{
template <typename T, typename Container>
class stack
{
public:
    using value_type      = typename Container::value_type;
    using reference       = typename Container::reference;
    using const_reference = typename Container::const_reference;
    using size_type       = typename Container::size_type;
    using container_type  = Container;

    /**
     * @brief Default constructor. Value-initializes the container.
     */
    stack() : stack(Container()) { }

    /**
     * @brief Copy-constructs the underlying container c with the contents of \p cont.
     */
    explicit stack(Container const& cont) : c {cont} { }

    /**
     * @brief Move-constructs the underlying container c with \p cont .
     */
    explicit stack(Container&& cont) : c {etl::move(cont)} { }

    /**
     * @brief Copy constructor.
     */
    stack(stack const& other) = default;

    /**
     * @brief Move constructor.
     */
    stack(stack&& other) noexcept = default;

    /**
     * @brief
     */
    [[nodiscard]] auto empty() const -> bool { return c.empty(); }

    /**
     * @brief
     */
    [[nodiscard]] constexpr auto size() const -> size_type { return c.size(); }

    /**
     * @brief
     */
    [[nodiscard]] constexpr auto top() -> reference { return c.back(); }

    /**
     * @brief
     */
    [[nodiscard]] constexpr auto top() const -> const_reference { return c.back(); }

    /**
     * @brief
     */
    constexpr auto push(const value_type& x) -> void { c.push_back(x); }

    /**
     * @brief
     */
    constexpr auto push(value_type&& x) -> void { c.push_back(etl::move(x)); }

    /**
     * @brief
     */
    template <typename... Args>
    auto emplace(Args&&... args) -> decltype(auto)
    {
        return c.emplace_back(etl::forward<Args>(args)...);
    }

    /**
     * @brief
     */
    constexpr auto pop() -> void { c.pop_back(); }

    /**
     * @brief
     */
    constexpr auto swap(stack& s) noexcept(is_nothrow_swappable_v<Container>) -> void
    {
        using etl::swap;
        swap(c, s.c);
    }

protected:
    Container c;
};

/**
 * @brief These deduction guides are provided for stack to allow deduction from underlying
 * container type.
 */
template <typename Container>
stack(Container) -> stack<typename Container::value_type, Container>;

}  // namespace etl

#endif  // TAETL_STACK_HPP