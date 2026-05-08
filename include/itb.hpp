// itb.hpp — convenience meta-header pulling in every C++ wrapper.
//
// Consumer applications can include this single header to gain access
// to the full RAII surface (Encryptor, Seed, MAC, Blob, Streams,
// Library, Errors). For finer-grained control, include only the
// individual headers under `<itb/...>` that the consumer actually
// needs.
//
// The C ABI surface (opaque handles, status enum, free functions) is
// available via `<itb.h>` — that header is consumed verbatim from
// the C binding via sync_header.sh and is `extern "C"` guarded for
// safe inclusion from C++ translation units.

#pragma once

#include <itb/errors.hpp>
#include <itb/library.hpp>
#include <itb/seed.hpp>
#include <itb/mac.hpp>
#include <itb/cipher.hpp>
#include <itb/encryptor.hpp>
#include <itb/streams.hpp>
#include <itb/blob.hpp>
