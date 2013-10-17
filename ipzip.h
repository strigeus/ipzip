// IpZip - TCP/IP Packet Compressor with LZ4 support.
// Copyright (c) 2013, Ludvig Strigeus
// Portions Copyright (c) 2011-2013, Yann Collet.
//
// BSD 2-Clause License (http://www.opensource.org/licenses/bsd-license.php)
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


// ---- WHAT IS IPZIP? ----
// IpZip is a compressor optimized for compressing TCP/IP packets. It combines
// several different ideas. The compression is completely stateless, so prior
// packets are not needed to decompress future packets, i.e. packet loss is not
// an issue. IpZip is designed to compress small packets around ~1500 bytes
// large. In all cases (even for invalid packets or random input data) will the
// decompressed result be bit-identical to the input. If compression is not
// possible, the overhead of using IpZip is exactly one byte.
// IpZip recomputes the TCP/IP checksums to avoid storing them in the packet,
// so IpZip packets need to be transported over a reliable transport mechanism.
// This uses quite some CPU and can optionally be disabled.
//
// One use case for IpZip is to compress traffic over a VPN link.
//
// The following ideas are employed:
// 1) IP/TCP/UDP Header Compression exploits redundancy in the packet headers
//    and tries to represent them in a more compact form. This roughly halves
//    the packet header size on average, from 40 bytes to around 20 bytes for
//    TCP, or even less for UDP. To facilitate this process, IpZip needs
//    knowledge of the IP address of one endpoint, as well as the direction the
//    packet is traveling. This information is not required, but if provided,
//    gives better compression. LZ77 based compressors don't do a good job on
//    TCP/IP headers as they do not contain a lot of redundant information.
// 2) The LZ4 algorithm is used to compress the rest of the packet payload.
//    This is a very fast algorithm that still gives reasonably good compress
//    ratios, although for packet sizes as small as 1500 bytes, it does not
//    have a lot of possibilities for compression, so it doesn't make wonders.
// 3) To compensate for the slim opportunities for redundancy in small packets,
//    the LZ4 compressor can optionally use a static dictionary. This
//    dictionary is seeded with a bunch of common strings seen in HTTP traffic,
//    and facilitates compression of HTTP headers.
//

// ---- BENCHMARK ----
// This benchmark is run on a single core on an Intel Core i7 860.
// HeaderCompression + LZ4 + Dictionary:
//   Compress:   442.423798 MB/s.
//   Decompress: 1839.497314 MB/s.
//   Result:     239984490 => 219007105 (91.258850%, saved 20977385 bytes)
// HeaderCompression + LZ4:
//   Compress:   451.330933 MB/s.
//   Decompress: 1920.994507 MB/s.
//   Result:     239984490 => 224107177 (93.384033%, saved 15877313 bytes)
// HeaderCompression only:
//   Compress:   2816.371094 MB/s.
//   Decompress: 2071.843018 MB/s.
//   Result:     239984490 => 232643052 (96.940865%, saved 7341438 bytes)
// HeaderCompression only. TCP checksum optimization disabled:
//   Compress:   5623.430664 MB/s.
//   Decompress: 3150.432373 MB/s.
//   Result:     239984490 => 233802332 (97.423935%, saved 6182158 bytes)
// LZ4 only:
//   Compress:   457.206451 MB/s.
//   Decompress: 7425.835938 MB/s.
//   Result:     239984490 => 231889959 (96.627060%, saved 8094531 bytes)

#ifndef IPZIP_H_
#define IPZIP_H_

#include <stdlib.h>

typedef struct Ipzip Ipzip;

// Create an IpZip instance. This object should be passed to the
// other IpZip functions. The same IpZip object can not be used by
// two threads concurrently.
Ipzip *IpzipCreate(void);

// Destroy the IpZip instance.
void IpzipDestroy(Ipzip *ipzip);

// Returns the necessary destination buffer size required to compress
// data of length |source_len|. The buffer passed to |dest| in IpzipCompress
// needs to be this large.
size_t IpzipCompressBufferSize(size_t source_len);

// Disable checksumming, gain some speed and lose some efficiency.
#define IPZIP_COMPRESS_NO_CKSUM 1
// Disable LZ4 compression step.
#define IPZIP_COMPRESS_NO_LZ4   2
// Disable LZ4 dictionary.
#define IPZIP_COMPRESS_NO_DICT  4
// Turn off lz4 compression adaptively if it has little effect, gains speed.
// (Not implemented)
#define IPZIP_COMPRESS_ADAPTIVE 8

// Compress a packet with IpZip. The packet is read from |source|, |source_len|
// and output written to |dest|.|dest| must be large enough, given by
// |IpzipCompressBufferSize|. Returns number of bytes after compression. In
// case of incompressible data, the output will be exactly one byte larger than
// the input. |source_len| needs to be larger than 0.
// |client_addr| can be set to an IP which is either the source or
// destination of a packet. |send_by_client| should be 1 if the packet
// originates from |client_addr|, or else 0. It's not necessary that
// |client_addr| is completely accurate, but it helps compression.
// In any case must the same values for |client_addr| and |sent_by_client|
// be sent to the decompressor in order to decompress the packet.
// |compress_flags| can be set to the IPZIP_COMPRESS_* flags above
// to change the behavior of the function.
size_t IpzipCompress(Ipzip *ipzip,
                     const unsigned char *source, size_t source_len, unsigned char *dest,
                     unsigned char client_addr[4], int sent_by_client, int compress_flags);

// Decompress a packet compressed with IpZip.
// Returns 0 on failure. Will fail only on invalid input. Will never
// fail with data returned from IpzipCompress.
// |source| and |source_len| point at the source buffer where the
// compressed data is stored.
// The compressed data is written to |dest|, |dest_len|. If the output
// buffer is too small the function fails.
// |client_addr| and |sent_by_client| should be set to the same values
// that were used when the packet was compressed.
size_t IpzipDecompress(Ipzip *ipzip,
                       const unsigned char *source, size_t source_len,
                       unsigned char *dest, size_t dest_len,
                       unsigned char client_addr[4], int sent_by_client);

#endif  // IPZIP_H_
