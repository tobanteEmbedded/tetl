// SPDX-License-Identifier: BSL-1.0

#include <etl/array.hpp>
#include <etl/iterator.hpp>
#include <etl/numbers.hpp>
#include <etl/numeric.hpp>
#include <etl/span.hpp>
#include <etl/vector.hpp>

#include <stdio.h>

template <typename T, unsigned Channels, unsigned Frames>
struct fixed_audio_buffer {
    using value_type         = T;
    using size_type          = etl::size_t;
    using frame_type         = etl::array<T, Channels>;
    using const_frame_type   = etl::array<T const, Channels>;
    using channel_type       = etl::span<T, Frames>;
    using const_channel_type = etl::span<T const, Frames>;

    fixed_audio_buffer() = default;

    [[nodiscard]] auto size_channels() const -> size_type { return Channels; }
    [[nodiscard]] auto size_frames() const -> size_type { return Frames; }
    [[nodiscard]] auto size_samples() const -> size_type { return size_channels() * size_frames(); }

    [[nodiscard]] auto frame(size_type index) { return make_frame(index); }
    [[nodiscard]] auto frame(size_type index) const { return make_frame(index); }

    [[nodiscard]] auto channel(size_type ch)
    {
        return channel_type(etl::next(data(buffer_), static_cast<etl::ptrdiff_t>(ch * Frames)), Frames);
    }

    [[nodiscard]] auto channel(size_type ch) const
    {
        return const_channel_type(etl::next(data(buffer_), static_cast<etl::ptrdiff_t>(ch * Frames)), Frames);
    }

    [[nodiscard]] auto operator()(size_type ch, size_type s) -> value_type& { return channel(ch)[s]; }
    [[nodiscard]] auto operator()(size_type ch, size_type s) const -> value_type const& { return channel(ch)[s]; }

private:
    [[nodiscard]] auto make_frame(size_type s) const
    {
        auto frame = frame_type {};
        for (size_type ch { 0 }; ch < size_channels(); ++ch) { frame[ch] = (*this)(ch, s); }
        return frame;
    }

    etl::array<value_type, static_cast<etl::size_t>(Channels* Frames)> buffer_ {};
};

auto main() -> int
{
    etl::static_vector<double, 16> vec;
    vec.push_back(etl::numbers::pi);
    vec.push_back(2.0);
    vec.push_back(3.0);
    vec.push_back(4.0);

    auto sum = etl::accumulate(vec.begin(), vec.end(), 0.0);
    printf("%f\n", sum);

    auto buffer = fixed_audio_buffer<float, 2, 32> {};
    printf("%zu\n", etl::size(buffer.channel(0)));
    return 0;
}
