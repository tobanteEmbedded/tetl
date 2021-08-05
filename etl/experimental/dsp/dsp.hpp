// Copyright (c) Tobias Hienzsch. All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
//  * Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
//  * Redistributions in binary form must reproduce the above copyright
//    notice, this list of conditions and the following disclaimer in the
//    documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND ANY
// EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE FOR ANY
// DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
// LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
// OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

#ifndef TETL_DSP_DSP_HPP
#define TETL_DSP_DSP_HPP

#include "etl/version.hpp"

#include "etl/array.hpp"
#include "etl/cstddef.hpp"
#include "etl/tuple.hpp"
#include "etl/utility.hpp"

namespace etl::experimental::dsp {
struct identity {
    constexpr identity() = default;

    template <typename T>
    constexpr auto operator()(T val) const
    {
        return val;
    }
};

template <typename T = float>
struct constant {
    constexpr constant(T val) : val_ { val } { }

    template <typename... Args>
    constexpr auto operator()(Args... /*unused*/) const
    {
        return val_;
    }

private:
    T const val_;
};

namespace literals {
    constexpr auto operator""_K(long double val) -> constant<long double>
    {
        return constant { val };
    }
    constexpr auto operator""_K(unsigned long long val)
        -> constant<unsigned long long>
    {
        return constant { val };
    }
} // namespace literals

template <typename L, typename R>
struct pipe {
    constexpr pipe(L lhs, R rhs) : lhs_ { lhs }, rhs_ { rhs } { }

    template <typename... T>
    constexpr auto operator()(T... val)
    {
        return call_rhs(lhs_(val...));
    }

private:
    template <typename... T>
    constexpr auto call_rhs(T... val)
    {
        return rhs_(etl::forward<T>(val)...);
    }

    L lhs_;
    R rhs_;
};

template <typename L, typename R>
constexpr auto operator|(L lhs, R rhs)
{
    return pipe<L, R> { lhs, rhs };
}

template <typename T, int Z>
struct delay {
    constexpr delay() = default;
    constexpr delay(T v)
    {
        for (auto& val : zBuffer_) { val = v; }
    }

    constexpr auto operator()(T const& val)
    {
        zBuffer_[head_] = val;
        if (++head_ > Z) { head_ = 0; }

        if (++tail_ > Z) { tail_ = 0; }
        return zBuffer_[tail_];
    };

private:
    using z_buffer_t = etl::array<T, static_cast<size_t>(Z) + 1>;
    typename z_buffer_t::size_type head_ = 0;
    typename z_buffer_t::size_type tail_ = 0;
    z_buffer_t zBuffer_                  = {};
};

template <int I, typename T = float>
constexpr auto Z(T val = T {})
{
    static_assert(I <= 0, "Delay should be negative");
    return delay<T, I * -1> { val };
}

template <typename T = float>
struct feedback_drain {
    constexpr feedback_drain() = default;
    constexpr auto operator()(T const& in)
    {
        auto const out = in + feedback_;
        feedback_      = T { 0 };
        return out;
    }
    constexpr auto push(T const& val) { feedback_ = val; }

private:
    T feedback_ = {};
};

template <typename T = float>
struct feedback_tap {
    constexpr feedback_tap(feedback_drain<T>& d) : drain_ { d } { }
    constexpr auto operator()(T const& in) const
    {
        drain_.push(in);
        return in;
    }

private:
    feedback_drain<T>& drain_;
};

namespace detail {
    // template <typename Tuple, etl::size_t... Indices, typename... Tn>
    // void for_each_fork_impl(Tuple&& tuple, etl::index_sequence<Indices...>,
    //                         Tn... val)
    // {
    //     (etl::get<Indices>(etl::forward<Tuple>(tuple))(val...), ...);
    // }
    template <typename Tuple, typename... Tn>
    void for_each_fork(Tuple&& /*tuple*/, Tn... /*val*/)
    {
        // constexpr etl::size_t N
        //     = etl::tuple_size<etl::remove_reference_t<Tuple>>::value;
        // for_each_fork_impl(etl::forward<Tuple>(tuple),
        //                    etl::make_index_sequence<N> {}, val...);
    }

    template <typename... T>
    struct fork_impl {
        fork_impl(T&&... val) : nodes_ { etl::forward<T>(val)... } { }

        template <typename... Tn>
        void operator()(Tn... val) const
        {
            for_each_fork(nodes_, val...);
        }

    private:
        etl::tuple<T...> nodes_;
    };
} // namespace detail

template <typename... T>
auto fork(T&&... val)
{
    return detail::fork_impl<T...> { etl::forward<T>(val)... };
}

} // namespace etl::experimental::dsp

#endif // TETL_DSP_DSP_HPP
