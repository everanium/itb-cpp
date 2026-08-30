/* encrypt_message throughput vs plaintext size (Single Message
 * profile) at 1 MiB / 16 MiB / 64 MiB. */

#include <exception>

#include "bench_util.hpp"

int main()
{
    try {
        /* Bench-scale allocation churn leaks Go scratch heap
         * unboundedly without a soft memory cap + aggressive GC; the
         * return values report the previous settings, not an error. */
        (void)itb::set_memory_limit(512LL << 20); /* 512 MiB soft cap */
        (void)itb::set_gc_percent(20);            /* aggressive GC */

        itb::Pipeline pipe = itb::Pipeline::init(
            bench_profile_name("singlemsg-triple-nomac-v1"),
            bench_build_opts());
        bench_header();
        static const std::size_t sizes[] = {
            std::size_t{1} << 20, std::size_t{16} << 20, std::size_t{64} << 20,
        };
        for (std::size_t size : sizes) {
            std::vector<std::uint8_t> plain(size);
            bench_csprng_fill(plain);
            /* wire is reusable scratch shared by every iteration of a
             * size case: sized once to the expansion bound, then
             * rewritten in place by encrypt_message_into — no
             * per-iteration allocation. */
            std::vector<std::uint8_t> wire(itb::out_bound(size));
            bench_case("message", size, [&] {
                (void)pipe.encrypt_message_into(itb::as_bytes(plain),
                                                itb::as_writable_bytes(wire));
            });
            /* Pre-encrypt once outside the decrypt timing loop so only
             * the decrypt call is measured; dec_out is reusable scratch. */
            std::size_t dec_wire_len = pipe.encrypt_message_into(
                itb::as_bytes(plain), itb::as_writable_bytes(wire));
            std::vector<std::uint8_t> dec_out(size);
            bench_case("message-dec", size, [&] {
                (void)pipe.decrypt_message_into(
                    itb::as_bytes(std::span<const std::uint8_t>(wire.data(),
                                                                dec_wire_len)),
                    itb::as_writable_bytes(dec_out));
            });
        }
        return 0;
    } catch (const std::exception &e) {
        std::fprintf(stderr, "bench_message: %s\n", e.what());
        return 1;
    }
}
