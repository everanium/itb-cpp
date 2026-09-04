/*
 * eitb — command-line demonstrator for the ITB C++ binding.
 *
 * Subcommands:
 *
 *   eitb version                                   library + binding versions
 *   eitb profiles                                  registered profile catalogue
 *   eitb encrypt <profile> <in-file> <out-file>    Single Message encrypt
 *   eitb decrypt <profile> <blob-hex> <in-file> <out-file>
 *
 * `encrypt` prints the session blob to stderr as hex; feed that hex
 * back to `decrypt` on the receiving side. `profiles` lists the
 * registered profile catalogue one name per line; the profiles that
 * carry a cipher surface are the ones `encrypt` / `decrypt` accept.
 */

#include <cstdio>
#include <cstring>
#include <exception>
#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "itb.hpp"

namespace {

int usage()
{
    std::fprintf(stderr,
                 "usage: eitb version\n"
                 "       eitb profiles\n"
                 "       eitb encrypt <profile> <in-file> <out-file>\n"
                 "       eitb decrypt <profile> <blob-hex> <in-file> <out-file>\n");
    return 2;
}

/* Reads a whole file into a byte vector. Returns false on error
 * (message printed). */
bool read_file(const char *path, std::vector<std::uint8_t> &out)
{
    out.clear();
    std::FILE *f = std::fopen(path, "rb");
    if (f == nullptr) {
        std::fprintf(stderr, "eitb: cannot open %s\n", path);
        return false;
    }
    std::uint8_t chunk[65536];
    for (;;) {
        std::size_t n = std::fread(chunk, 1, sizeof(chunk), f);
        out.insert(out.end(), chunk, chunk + n);
        if (n == 0) {
            break;
        }
    }
    const bool bad = std::ferror(f) != 0;
    std::fclose(f);
    if (bad) {
        std::fprintf(stderr, "eitb: read error on %s\n", path);
        return false;
    }
    return true;
}

/* Profiles whose canonical name begins with "streaming-" route
 * through the one-shot streaming buffered pair instead of the Single
 * Message pair. */
bool is_streaming_profile(const char *profile)
{
    return std::string_view(profile).starts_with("streaming-");
}

/* Recursively creates the parent directory of `out` (analogue of
 * `mkdir -p $(dirname out)`). Silent when the directory already
 * exists; returns 0 on success and 1 on genuine filesystem failure. */
int ensure_parent_dir(const char *out)
{
    std::filesystem::path parent = std::filesystem::path(out).parent_path();
    if (parent.empty()) {
        return 0;
    }
    std::error_code ec;
    std::filesystem::create_directories(parent, ec);
    if (ec) {
        std::fprintf(stderr, "eitb: mkdir %s: %s\n", parent.c_str(),
                     ec.message().c_str());
        return 1;
    }
    return 0;
}

/* Writes a whole buffer to a file. Returns 0 on success. */
int write_file(const char *path, const std::vector<std::uint8_t> &buf)
{
    if (ensure_parent_dir(path) != 0) {
        return 1;
    }
    std::FILE *f = std::fopen(path, "wb");
    if (f == nullptr) {
        std::fprintf(stderr, "eitb: cannot create %s\n", path);
        return 1;
    }
    if (!buf.empty() && std::fwrite(buf.data(), 1, buf.size(), f) != buf.size()) {
        std::fclose(f);
        std::fprintf(stderr, "eitb: write error on %s\n", path);
        return 1;
    }
    if (std::fclose(f) != 0) {
        std::fprintf(stderr, "eitb: close error on %s\n", path);
        return 1;
    }
    return 0;
}

int cmd_version()
{
    std::printf("libitb %s\n", itb::version().c_str());
    std::printf("itb-cpp %s\n", ITB_CPP_VERSION);
    return 0;
}

/* Prints the registered profile catalogue one name per line in the
 * sorted order itb::profiles returns. The catalogue arrives as a JSON
 * array of strings; profile names are restricted to [a-z0-9-], so
 * each quoted run is one complete name and no escape handling is
 * needed. */
int cmd_profiles()
{
    const std::string json = itb::profiles();
    std::size_t pos = 0;
    for (;;) {
        const std::size_t open = json.find('"', pos);
        if (open == std::string::npos) {
            break;
        }
        const std::size_t close = json.find('"', open + 1);
        if (close == std::string::npos) {
            break;
        }
        std::printf("%s\n", json.substr(open + 1, close - open - 1).c_str());
        pos = close + 1;
    }
    return 0;
}

/* Defensive Go-runtime pacing for cipher workloads on large files:
 * a soft memory cap + aggressive GC keep the scratch heap bounded.
 * The setter return values report the previous settings, not an
 * error. */
void cap_go_runtime()
{
    (void)itb::set_memory_limit(512LL << 20); /* 512 MiB soft cap */
    (void)itb::set_gc_percent(20);            /* aggressive GC */
}

int cmd_encrypt(const char *profile, const char *infile, const char *outfile)
{
    cap_go_runtime();
    std::vector<std::uint8_t> plain;
    if (!read_file(infile, plain)) {
        return 1;
    }
    itb::Pipeline pipe = itb::Pipeline::init(profile);
    std::vector<std::uint8_t> wire = is_streaming_profile(profile)
        ? pipe.encrypt_stream_pump(itb::as_bytes(plain))
        : pipe.encrypt_message(itb::as_bytes(plain));
    int rc = write_file(outfile, wire);
    if (rc == 0) {
        for (std::uint8_t b : pipe.save()) {
            std::fprintf(stderr, "%02x", static_cast<unsigned>(b));
        }
        std::fprintf(stderr, "\n");
        std::printf("encrypted %s -> %s (%zu -> %zu bytes)\n", infile, outfile,
                    plain.size(), wire.size());
    }
    return rc;
}

int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    return -1;
}

int cmd_decrypt(const char *profile, const char *blob_hex,
                const char *infile, const char *outfile)
{
    cap_go_runtime();
    const std::size_t hex_len = std::strlen(blob_hex);
    if (hex_len == 0 || hex_len % 2 != 0) {
        std::fprintf(stderr, "eitb: blob hex has odd or zero length\n");
        return 1;
    }
    std::vector<std::uint8_t> blob(hex_len / 2);
    for (std::size_t i = 0; i < blob.size(); i++) {
        const int hi = hex_nibble(blob_hex[2 * i]);
        const int lo = hex_nibble(blob_hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            std::fprintf(stderr, "eitb: invalid blob hex\n");
            return 1;
        }
        blob[i] = static_cast<std::uint8_t>((hi << 4) | lo);
    }
    std::vector<std::uint8_t> wire;
    if (!read_file(infile, wire)) {
        return 1;
    }
    /* The profile shape travels inside the blob; the profile argument
     * only selects the Single Message or streaming cipher pair. */
    itb::Pipeline pipe = itb::Pipeline::load(itb::as_bytes(blob));
    std::vector<std::uint8_t> plain = is_streaming_profile(profile)
        ? pipe.decrypt_stream_pump(itb::as_bytes(wire))
        : pipe.decrypt_message(itb::as_bytes(wire));
    int rc = write_file(outfile, plain);
    if (rc == 0) {
        std::printf("decrypted %s -> %s (%zu -> %zu bytes)\n", infile, outfile,
                    wire.size(), plain.size());
    }
    return rc;
}

} // namespace

int main(int argc, char **argv)
{
    try {
        if (argc < 2) {
            return usage();
        }
        if (std::strcmp(argv[1], "version") == 0 && argc == 2) {
            return cmd_version();
        }
        if (std::strcmp(argv[1], "profiles") == 0 && argc == 2) {
            return cmd_profiles();
        }
        if (std::strcmp(argv[1], "encrypt") == 0 && argc == 5) {
            return cmd_encrypt(argv[2], argv[3], argv[4]);
        }
        if (std::strcmp(argv[1], "decrypt") == 0 && argc == 6) {
            return cmd_decrypt(argv[2], argv[3], argv[4], argv[5]);
        }
        return usage();
    } catch (const std::exception &e) {
        std::fprintf(stderr, "eitb: %s\n", e.what());
        return 1;
    }
}
