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

#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "ipzip.h"
#include "ipzip_lz4_impl.h"

// These are encoded in one byte.
#define IPZIP_MORE_FLAGS  0x01
#define IPZIP_FLAG_HIGHIPNEQ    0x02
#define IPZIP_FLAG_TTL_FRAG    0x04

// Same position as PUSH in TCP Header
#define IPZIP_FLAG_TCP_PUSH    0x08

#define IPZIP_FLAG_TCP_PORT_FULL 0x10
#define IPZIP_FLAG_TCP_PORT_80   0x20
#define IPZIP_FLAG_TCP_PORT_443  0x30
#define IPZIP_FLAG_TCP           0x40

#define IPZIP_FLAG_LZ4           0x80

#define IPZIP_FLAG_UDP_PORT      0x08
#define IPZIP_FLAG_UDP           0x10

// These require another byte.
#define IPZIP_FLAG_DSCP_ECN  0x100
#define IPZIP_FLAG_WRONG_IP  0x200

#define IPZIP_FLAG_TCP_FLAGS 0x400
#define IPZIP_FLAG_TCP_CKSUM 0x800

#define IPZIP_FLAG_UDP_NOSUM 0x400
#define IPZIP_FLAG_UDP_CKSUM 0x800

#define IPZIP_FLAG_CONTEXT_AWARE 0x1000

typedef unsigned int uint32;
typedef unsigned short uint16;

// This doesn't seem to make things faster...
#if defined(_MSC_VER) && 0
#define READ_WORD(x) lz4_bswap16(A16(x))
#define WRITE_WORD(addr, x) (A16(addr) = lz4_bswap16(x))
#define READ_DWORD(x) lz4_bswap32(A32(x))
#define WRITE_DWORD(addr, x) (A32(addr) = lz4_bswap32(x))
#else
#define READ_WORD(x) ((x)[0]<<8 | (x)[1])
#define WRITE_WORD(addr, x) { unsigned char *ww = (addr); int xx = (x); ww[1] = (xx); ww[0] = (xx>>=8);}
#define WRITE_DWORD(addr, x) { unsigned char *ww = (addr); uint32 xx = (x); ww[3] = (xx); ww[2] = (xx>>=8); ww[1] = (xx>>=8); ww[0] = (xx>>=8);}
#endif
#define WRITE_NATIVE_WORD(addr, x) (A16(addr) = (x))
#define COPY_DWORD(d, s)    (A32(d) = A32(s))
#define COPY_WORD(d, s)     (A16(d) = A16(s))
#define COPY_QWORD(d, s)    (A64(d) = A64(s))
#define COMPARE_DWORD(d, s) (A32(d) == A32(s))
#define COMPARE_WORD(d, s)  (A16(d) == A16(s))

#define IPZIP_MKDWORD(a,b,c,d) ((a)|(b)<<8|(c)<<16|(d)<<24)

// Compute the IP checksum of the bytes in |source|.
// source_size needs to sufficiently short or the computation will wrap.
// Returns zero if checksum is valid.
static uint16 CalcChecksum(uint32 sum, const unsigned char *source, int source_size) {
  uint16 *s = (uint16*)source;
  while (source_size >= 32) {
    sum += A16(s+0) + A16(s+1) + A16(s+2) + A16(s+3) +
           A16(s+4) + A16(s+5) + A16(s+6) + A16(s+7) +
           A16(s+8) + A16(s+9) + A16(s+10) + A16(s+11) +
           A16(s+12) + A16(s+13) + A16(s+14) + A16(s+15);
    s += 16;
    source_size -= 32;
  }
  while (source_size >= 2) {
    sum += A16(s+0);
    s += 1;
    source_size -= 2;
  }
  if (source_size) {
    unsigned char tmp[2] = {*(unsigned char*)s, 0};
    sum += A16(tmp);
  }
  sum = (unsigned short)(sum & 0xFFFF) + (sum >> 16);
  sum += (sum >> 16);
  sum = ~sum & 0xffff;
  return sum;
}

// Compute the TCP or UDP Checksum. It needs to return 0xffff instead of 0x0.
static uint32 CalcTcpUdpChecksum(const unsigned char *source, int source_size) {
  // Include pseudo IP header
  int v = source_size - 20 + source[9];
  unsigned char tmp[2] = {v >> 8, v};
  uint32 sum = A16(source + 12) +
               A16(source + 14) +
               A16(source + 16) +
               A16(source + 18) +
               A16(tmp);
  sum = CalcChecksum(sum, source + 20, source_size - 20);
  sum -= (sum == 0);
  return sum;
}

// TCP Encoding:
// +----------------+
// | Z 1 RR P F L C |
// +----------------+
// Z =  Payload compressed with LZ4
// C =  Read Flags2 byte
// RR = 0 = full port, 1 = high port byte zero, 2 = port 80, 3 = port 443
// P  = TCP PUSH flag set
// F  = (PACKET_FROM_CLIENT && (C == 0)) ? (TTL==0x80 && DONT_FRAGMENT==1) : (DONT_FRAGMENT);
// L  = (SourceIP&0xFFFF0000) == (DestIP&0xFFFF0000)
//
// UDP Encoding:
// +-----------------+
// | Z 0 0 1 P F L C |
// +-----------------+
// Z  = Payload compressed with LZ4
// C  = Read Flags2 byte
// P  = 0 = full port, 1 = high port byte zero
// F  = (PACKET_FROM_CLIENT && (C == 0)) ? (TTL==0x80 && DONT_FRAGMENT==1) : (DONT_FRAGMENT);
// L  = (SourceIP&0xFFFF0000) == (DestIP&0xFFFF0000)
//
// Disable Header Compression:
// +-----------------+
// | Z 0 0 0 0 0 0 C |
// +-----------------+
// Z = Payload compressed with LZ4
// C = Read Flags2 byte
//
// Flags2 byte:
// P0 = Read DsCP_ECN
// P1 = Read Source IP address
// P2 = Read TCP Flags / Header Size
// P3 = TCP checksum
// P4 = Static dictionary used
// P5 =
// P6 =
// P7 = <Read another byte with more flags>

static const char static_dictionary[] = {
66, 85, 83, 32, 67, 85, 82, 32, 67, 79, 78, 111, 32, 70, 73, 78, 32, 73, 86, 68,
111, 32, 79, 78, 76, 32, 79, 85, 82, 32, 80, 72, 89, 32, 83, 65, 77, 111, 32,
84, 69, 76, 111, 34, 13, 10, 99, 97, 99, 104, 101, 32, 34, 44, 67, 80, 61, 34,
67, 65, 79, 32, 68, 83, 80, 32, 76, 65, 87, 32, 67, 85, 82, 32, 65, 68, 77, 32,
73, 86, 65, 111, 32, 73, 86, 68, 111, 32, 67, 79, 78, 111, 32, 79, 84, 80, 111,
32, 79, 85, 82, 32, 68, 69, 76, 105, 32, 80, 85, 66, 105, 32, 79, 84, 82, 105,
32, 66, 85, 83, 67, 78, 84, 32, 83, 84, 65, 32, 72, 69, 65, 32, 80, 82, 69, 32,
76, 79, 67, 32, 71, 79, 86, 32, 79, 84, 67, 32, 34, 13, 10, 112, 108, 97, 105,
110, 32, 79, 84, 73, 32, 68, 83, 80, 32, 67, 79, 82, 32, 73, 86, 65, 32, 79, 85,
82, 32, 73, 78, 68, 32, 67, 79, 77, 32, 34, 85, 84, 70, 45, 56, 44, 32, 112,
114, 111, 120, 121, 45, 114, 101, 118, 97, 108, 105, 100, 97, 116, 101, 48, 44,
32, 110, 111, 45, 99, 97, 99, 104, 101, 61, 83, 101, 116, 45, 67, 111, 111, 107,
105, 101, 44, 32, 110, 111, 45, 115, 116, 111, 114, 101, 44, 32, 109, 117, 115,
116, 45, 114, 101, 118, 97, 108, 105, 100, 97, 116, 101, 44, 32, 115, 45, 109,
97, 120, 97, 103, 101, 61, 48, 44, 32, 112, 111, 115, 116, 45, 99, 104, 101, 99,
107, 61, 48, 44, 32, 112, 114, 101, 45, 99, 104, 101, 99, 107, 61, 48, 44, 32,
112, 117, 98, 108, 105, 99, 44, 32, 110, 111, 45, 116, 114, 97, 110, 115, 102,
111, 114, 109, 44, 32, 112, 114, 105, 118, 97, 116, 101, 13, 10, 47, 119, 51,
99, 47, 112, 51, 112, 46, 120, 109, 108, 66, 85, 83, 32, 85, 78, 73, 32, 78, 65,
86, 32, 83, 84, 65, 32, 73, 78, 84, 34, 78, 79, 73, 32, 68, 83, 80, 32, 67, 79,
82, 32, 65, 68, 77, 111, 32, 83, 65, 77, 111, 32, 85, 78, 82, 111, 32, 79, 84,
82, 111, 32, 66, 85, 83, 32, 67, 79, 77, 32, 78, 65, 86, 32, 68, 69, 77, 32, 83,
84, 65, 32, 80, 82, 69, 34, 13, 10, 86, 84, 97, 103, 58, 32, 97, 99, 99, 101,
115, 115, 45, 99, 111, 110, 116, 114, 111, 108, 45, 97, 108, 108, 111, 119, 45,
111, 114, 105, 103, 105, 110, 58, 32, 42, 13, 10, 83, 111, 117, 114, 99, 101,
45, 65, 103, 101, 58, 32, 48, 32, 51, 48, 50, 32, 77, 111, 118, 101, 100, 32,
84, 101, 109, 112, 111, 114, 97, 114, 105, 108, 121, 51, 48, 50, 32, 70, 111,
117, 110, 100, 13, 10, 80, 120, 45, 85, 110, 99, 111, 109, 112, 114, 101, 115,
115, 45, 79, 114, 105, 103, 105, 110, 58, 32, 67, 65, 79, 32, 68, 83, 80, 32,
67, 79, 82, 80, 83, 65, 97, 32, 80, 83, 68, 97, 32, 73, 86, 65, 105, 32, 73, 86,
68, 105, 32, 67, 79, 78, 105, 32, 79, 85, 82, 32, 79, 84, 82, 105, 32, 73, 78,
68, 32, 80, 72, 89, 32, 79, 78, 76, 32, 85, 78, 73, 32, 70, 73, 78, 65, 68, 77,
32, 68, 69, 86, 32, 80, 83, 65, 83, 84, 65, 34, 13, 10, 99, 111, 110, 116, 101,
110, 116, 45, 116, 121, 112, 101, 58, 32, 111, 99, 115, 112, 45, 114, 101, 115,
112, 111, 110, 115, 101, 13, 10, 52, 48, 48, 32, 66, 97, 100, 32, 114, 101, 113,
117, 101, 115, 116, 51, 48, 52, 32, 78, 111, 116, 32, 77, 111, 100, 105, 102,
105, 101, 100, 73, 102, 45, 77, 111, 100, 105, 102, 105, 101, 100, 45, 83, 105,
110, 99, 101, 58, 32, 44, 42, 47, 42, 59, 113, 61, 48, 46, 49, 13, 10, 34, 44,
32, 67, 80, 61, 34, 111, 32, 80, 83, 65, 111, 32, 80, 83, 68, 111, 32, 79, 85,
82, 32, 73, 78, 68, 32, 85, 78, 73, 32, 80, 85, 82, 32, 73, 78, 84, 32, 68, 69,
77, 32, 83, 84, 65, 32, 80, 82, 69, 32, 67, 79, 77, 32, 78, 65, 86, 32, 79, 84,
67, 32, 78, 79, 73, 32, 68, 83, 80, 32, 67, 79, 82, 34, 88, 83, 83, 45, 80, 114,
111, 116, 101, 99, 116, 105, 111, 110, 58, 32, 49, 59, 32, 109, 111, 100, 101,
61, 98, 108, 111, 99, 107, 13, 10, 71, 111, 111, 103, 108, 101, 45, 67, 114,
101, 97, 116, 105, 118, 101, 45, 73, 100, 58, 32, 112, 111, 108, 105, 99, 121,
114, 101, 102, 61, 34, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 110,
101, 116, 13, 10, 32, 74, 97, 110, 32, 50, 48, 49, 32, 70, 101, 98, 32, 50, 48,
49, 32, 77, 97, 114, 32, 50, 48, 49, 32, 65, 112, 114, 32, 50, 48, 49, 32, 77,
97, 121, 32, 50, 48, 49, 32, 74, 117, 110, 32, 50, 48, 49, 32, 74, 117, 108, 32,
50, 48, 49, 32, 65, 117, 103, 32, 50, 48, 49, 32, 83, 101, 112, 32, 50, 48, 49,
32, 79, 99, 116, 32, 50, 48, 49, 32, 78, 111, 118, 32, 50, 48, 49, 32, 68, 101,
99, 32, 50, 48, 49, 32, 77, 111, 110, 44, 32, 84, 117, 101, 44, 32, 87, 101,
100, 44, 32, 84, 104, 117, 44, 32, 70, 114, 105, 44, 32, 83, 97, 116, 44, 32,
83, 117, 110, 44, 32, 69, 116, 97, 103, 58, 32, 99, 108, 111, 115, 101, 13, 10,
75, 101, 101, 112, 45, 65, 108, 105, 118, 101, 58, 32, 116, 105, 109, 101, 111,
117, 116, 61, 53, 44, 32, 109, 97, 120, 61, 49, 48, 13, 10, 115, 115, 45, 67,
111, 110, 116, 114, 111, 108, 45, 65, 108, 108, 111, 119, 45, 79, 114, 105, 103,
105, 110, 58, 32, 42, 45, 106, 97, 118, 97, 115, 99, 114, 105, 112, 116, 59, 32,
99, 104, 97, 114, 115, 101, 116, 61, 13, 10, 76, 111, 99, 97, 116, 105, 111,
110, 58, 32, 104, 116, 116, 112, 58, 47, 47, 119, 119, 119, 46, 44, 112, 117,
98, 108, 105, 99, 44, 32, 109, 97, 120, 45, 97, 103, 101, 61, 58, 32, 116, 101,
120, 116, 47, 104, 116, 109, 108, 44, 97, 112, 112, 108, 105, 99, 97, 116, 105,
111, 110, 47, 120, 104, 116, 109, 108, 43, 120, 109, 108, 44, 97, 112, 112, 108,
105, 99, 97, 116, 105, 111, 110, 47, 120, 109, 108, 59, 113, 61, 48, 46, 57, 44,
42, 47, 42, 59, 113, 61, 48, 46, 56, 46, 112, 110, 103, 32, 72, 84, 84, 80, 47,
49, 46, 49, 13, 10, 65, 108, 116, 101, 114, 110, 97, 116, 101, 45, 80, 114, 111,
116, 111, 99, 111, 108, 58, 32, 56, 48, 58, 113, 117, 105, 99, 116, 45, 67, 111,
111, 107, 105, 101, 58, 32, 68, 105, 115, 112, 111, 115, 105, 116, 105, 111,
110, 58, 32, 97, 116, 116, 97, 99, 104, 109, 101, 110, 116, 13, 10, 84, 114, 97,
110, 115, 102, 101, 114, 45, 69, 110, 99, 111, 100, 105, 110, 103, 58, 32, 99,
104, 117, 110, 107, 101, 100, 69, 110, 99, 111, 100, 105, 110, 103, 58, 32, 103,
122, 105, 112, 58, 32, 42, 47, 42, 116, 101, 120, 116, 47, 104, 116, 109, 108,
59, 32, 99, 104, 97, 114, 115, 101, 116, 61, 117, 116, 102, 45, 56, 85, 84, 70,
45, 56, 46, 106, 112, 103, 32, 72, 84, 84, 80, 47, 49, 46, 49, 32, 50, 48, 48,
32, 79, 75, 13, 10, 83, 101, 114, 118, 101, 114, 58, 32, 65, 112, 97, 99, 104,
101, 13, 10, 88, 45, 67, 111, 110, 116, 101, 110, 116, 45, 84, 121, 112, 101,
45, 79, 112, 116, 105, 111, 110, 115, 58, 32, 110, 111, 115, 110, 105, 102, 102,
111, 99, 116, 101, 116, 45, 115, 116, 114, 101, 97, 109, 115, 104, 111, 99, 107,
119, 97, 118, 101, 45, 102, 108, 97, 115, 104, 13, 10, 82, 97, 110, 103, 101,
115, 58, 32, 98, 121, 116, 101, 115, 13, 10, 86, 105, 97, 58, 32, 41, 32, 71,
101, 99, 107, 111, 47, 59, 32, 114, 118, 58, 32, 100, 101, 102, 108, 97, 116,
101, 112, 110, 103, 44, 105, 109, 97, 103, 101, 47, 42, 59, 113, 61, 48, 46, 56,
44, 42, 47, 42, 59, 113, 61, 48, 46, 53, 13, 10, 80, 114, 97, 103, 109, 97, 58,
32, 110, 111, 45, 99, 97, 99, 104, 101, 32, 70, 105, 114, 101, 102, 111, 120,
47, 13, 10, 69, 84, 97, 103, 58, 32, 32, 83, 97, 102, 97, 114, 105, 47, 13, 10,
65, 103, 101, 58, 32, 49, 58, 32, 105, 109, 97, 103, 101, 47, 119, 101, 98, 112,
44, 42, 47, 42, 59, 113, 61, 48, 46, 56, 76, 101, 110, 103, 116, 104, 58, 32,
52, 51, 13, 10, 86, 97, 114, 121, 58, 32, 65, 99, 99, 101, 112, 116, 45, 69,
110, 99, 111, 100, 105, 110, 103, 44, 32, 40, 75, 72, 84, 77, 76, 44, 32, 108,
105, 107, 101, 32, 71, 101, 99, 107, 111, 41, 32, 67, 104, 114, 111, 109, 101,
47, 59, 32, 87, 79, 87, 54, 52, 41, 32, 65, 112, 112, 108, 101, 87, 101, 98, 75,
105, 116, 47, 40, 99, 111, 109, 112, 97, 116, 105, 98, 108, 101, 59, 32, 77, 83,
73, 69, 32, 40, 87, 105, 110, 100, 111, 119, 115, 32, 78, 84, 32, 84, 114, 105,
100, 101, 110, 116, 47, 59, 32, 46, 78, 69, 84, 32, 67, 76, 82, 32, 13, 10, 80,
51, 80, 58, 32, 67, 80, 61, 34, 78, 79, 73, 32, 68, 83, 80, 32, 67, 79, 82, 32,
78, 73, 68, 32, 67, 85, 82, 97, 32, 65, 68, 77, 97, 32, 68, 69, 86, 97, 32, 84,
65, 73, 97, 32, 80, 83, 65, 97, 32, 80, 83, 68, 97, 32, 79, 85, 82, 32, 76, 69,
71, 32, 78, 65, 86, 32, 73, 78, 84, 34, 76, 97, 110, 103, 117, 97, 103, 101, 58,
32, 101, 110, 45, 85, 83, 44, 101, 110, 59, 113, 61, 48, 46, 56, 13, 10, 13, 10,
76, 97, 115, 116, 45, 77, 111, 100, 105, 102, 105, 101, 100, 58, 32, 110, 110,
101, 99, 116, 105, 111, 110, 58, 32, 107, 101, 101, 112, 45, 97, 108, 105, 118,
101, 13, 10, 69, 120, 112, 105, 114, 101, 115, 58, 32, 45, 49, 13, 10, 67, 97,
99, 104, 101, 45, 67, 111, 110, 116, 114, 111, 108, 58, 32, 109, 97, 120, 45,
97, 103, 101, 61, 13, 10, 82, 101, 102, 101, 114, 101, 114, 58, 32, 104, 116,
116, 112, 58, 47, 47, 119, 119, 119, 46, 111, 114, 103, 32, 71, 77, 84, 13, 10,
85, 115, 101, 114, 45, 65, 103, 101, 110, 116, 58, 32, 77, 111, 122, 105, 108,
108, 97, 47, 13, 10, 72, 111, 115, 116, 58, 32, 119, 119, 119, 46, 99, 111, 109,
13, 10, 68, 97, 116, 101, 58, 32, 71, 69, 84, 32, 47, 13, 10, 65, 99, 99, 101,
112, 116, 45, 69, 110, 99, 111, 100, 105, 110, 103, 58, 32, 103, 122, 105, 112,
44, 100, 101, 102, 108, 97, 116, 101, 44, 115, 100, 99, 104, 13, 10, 67, 111,
110, 116, 101, 110, 116, 45, 84, 121, 112, 101, 58, 32, 105, 109, 97, 103, 101,
47, 106, 112, 101, 103, 13, 10
};

#define IPZIP_MAX_DICT_COMPRESS_SIZE 2048

#define IPZIP_LZ4_BUFFER_SIZE (1U<<(MEMORY_USAGE))
struct Ipzip {
  // Backup of LZ4's context
  U32 ctx[IPZIP_LZ4_BUFFER_SIZE/4];
  // The first bytes are always the static dict. Then is the work area.
  char work_mem[sizeof(static_dictionary) + IPZIP_MAX_DICT_COMPRESS_SIZE];
};

Ipzip *IpzipCreate(void) {
  const BYTE *ip;
  int i;
  Ipzip *ipzip = (Ipzip *)calloc(1, sizeof(Ipzip));
  if (!ipzip) return ipzip;
  ip = (BYTE*)static_dictionary;
  for(i = 0; i < sizeof(static_dictionary) - 3; i++)
    LZ4_putPosition((BYTE*)static_dictionary + i, ipzip->ctx, byU16, (BYTE*)static_dictionary);
  memcpy(ipzip->work_mem, static_dictionary, sizeof(static_dictionary));
  return ipzip;
}

void IpzipDestroy(Ipzip *ipzip) {

	if(ipzip == NULL) return;
	free(ipzip);
}

static int IpzipCompressBuffer(Ipzip *ipzip, const unsigned char *source, unsigned char *dest,
                               int inputSize, int flags) {
  U32 ctx[IPZIP_LZ4_BUFFER_SIZE/4];
  const char *lzbase = (char*)source, *lzsource = (char*)source;
  if (flags & IPZIP_FLAG_CONTEXT_AWARE) {
    memcpy(ctx, ipzip->ctx, IPZIP_LZ4_BUFFER_SIZE);
    memcpy(ipzip->work_mem + sizeof(static_dictionary), source, inputSize);
    lzbase = ipzip->work_mem;
    lzsource = lzbase + sizeof(static_dictionary);
  } else {
    memset(ctx, 0, IPZIP_LZ4_BUFFER_SIZE);
  }
  return LZ4_compress_generic(ctx, lzsource, lzbase, lzbase,
                              (char*)dest, inputSize, 0, notLimited, byU16, noPrefix);
}

static int IpzipDecompressBuffer(Ipzip *ipzip, unsigned const char *source, unsigned char *dest,
                                 int inputSize, int maxOutputSize, int flags) {
  int rv, tmp_out_size = maxOutputSize;
  char *destcur = (char *)dest, *destbase = (char *)dest;
  if (flags & IPZIP_FLAG_CONTEXT_AWARE) {
    tmp_out_size = IPZIP_MAX_DICT_COMPRESS_SIZE;
    destbase = ipzip->work_mem;
    destcur = destbase + sizeof(static_dictionary);
  }
  rv = LZ4_decompress_generic((char*)source, destcur, destbase, inputSize,
                                  tmp_out_size, endOnInputSize, noPrefix, full, 0);
  if ((rv >= 0) && (flags & IPZIP_FLAG_CONTEXT_AWARE)) {
    if (rv > maxOutputSize) return -1;
    memcpy(dest, ipzip->work_mem + sizeof(static_dictionary), rv);
  }
  return rv;
}


size_t IpzipCompressBufferSize(size_t source_len) {
  // Just add some safety margin on top of what LZ4 needs.
  return LZ4_COMPRESSBOUND(source_len) + 32;
}

#define UNABLE_TO_HANDLE() goto FALLBACK;

// Compress the buffer |source|, |source_len| into the target buffer |dest|.
// |dest| must be large enough.
// Returns number of bytes after compression.
size_t IpzipCompress(Ipzip *ipzip,
                     const unsigned char *source, size_t source_len, unsigned char *dest,
                     unsigned char client_addr[4], int sent_by_client, int compress_flags) {
  unsigned char *dest_org = dest;
  int protocol, flags, port, n;
  // We only support IPv4 with 5 word header, for now.
  if (source_len < 28 || source[0] != 0x45) UNABLE_TO_HANDLE();
  // Make sure length field is valid
  if (READ_WORD(source + 2) != source_len) UNABLE_TO_HANDLE();
  // Fragmented packets are not compressed. But let the Don't Fragment bit through.
  if (source[7] != 0 || (source[6] & ~0x40) != 0) UNABLE_TO_HANDLE();
  // Make sure the IP Checksum is valid. 0xffff is an ambiguous checksum that
  // we cannot reconstruct (both 0x0000 and 0xffff are valid, so skip those packets).
  if (CalcChecksum(0, source, 20) || READ_WORD(source+10) == 0xffff) UNABLE_TO_HANDLE();
  // Remember which predictions are wrong.
  flags = 0;
  // Differentiated Services Code Point (DSCP) and Explicit Congestion Notification (ECN)
  // Predicted to be zero.
  if (source[1] != 0) {
    flags |= IPZIP_FLAG_DSCP_ECN;
    *dest++ = source[1];
  }
  protocol = source[9];
  // Copy the identification field. It's random and can't be predicted.
  COPY_WORD(dest, source + 4); dest += 2;
  // source_ip is the ip of the client side source. Encoded as either 32 or 0 bits.
  {
    const unsigned char *source_ip = source + 16 - sent_by_client * 4, *dest_ip;
    if (!COMPARE_DWORD(source_ip, client_addr)) {
      COPY_DWORD(dest, source_ip); dest += 4;
      flags |= IPZIP_FLAG_WRONG_IP;
    }
    // Encode the dest IP, either with 16 or 32 bits.
    dest_ip   = source + 12 + sent_by_client * 4;
    if (!COMPARE_WORD(source_ip, dest_ip)) {
      COPY_WORD(dest, dest_ip); dest += 2;
      flags |= IPZIP_FLAG_HIGHIPNEQ;
    }
    COPY_WORD(dest, dest_ip + 2); dest += 2;
  }
  COPY_WORD(dest, &source[22 - sent_by_client*2]); dest += 2;  // Source port.
  port = READ_WORD(source + 20 + sent_by_client*2);            // Read dest port for later
  if (protocol == 6) { // TCP
    int tcp_flags;
    // TCP Packets are always 40 bytes at least.
    if (source_len < 40) UNABLE_TO_HANDLE();
    flags |= IPZIP_FLAG_TCP;
    // Encode the dest port.
    if (port == 80) {
      flags |= IPZIP_FLAG_TCP_PORT_80;
    } else if (port == 443) {
      flags |= IPZIP_FLAG_TCP_PORT_443;
    } else {
      *dest++ = (unsigned char)port;
      if (port >> 8) {
        *dest++ = (unsigned char)(port >> 8);
        flags |= IPZIP_FLAG_TCP_PORT_FULL;
      }
    }
    COPY_QWORD(dest, source + 24); dest += 8;               // Seq.nr. Ack.nr.
    tcp_flags = READ_WORD(source + 20 + 12);
    flags |= (tcp_flags & 0x08) ? IPZIP_FLAG_TCP_PUSH : 0;  // PUSH flag
    // Verify that header length has the value 0x5 and FIN/SYN/RST clear and ACK set
    if ((tcp_flags & 0xF017) != 0x5010) {
      *dest++ = ((tcp_flags >> 8) & 0xF0) | (tcp_flags & 0x7) | ((tcp_flags >> 1) & 0x8);
      flags |= IPZIP_FLAG_TCP_FLAGS;
    }
    // Reserved bits and URGENT aren't supported.
    if (tcp_flags & 0x0FE0 || (source[20+18] | source[20+19]) != 0) UNABLE_TO_HANDLE();
    COPY_WORD(dest, &source[20+14]); dest += 2;            // Window Size
    if ((compress_flags&IPZIP_COMPRESS_NO_CKSUM) ||
        CalcTcpUdpChecksum(source, source_len) != 0xffffffff) {
      COPY_WORD(dest, &source[20+16]); dest += 2;
      flags |= IPZIP_FLAG_TCP_CKSUM;
    }
    n = 40;

    // Try to guess if to use dictionary or not, by using some simple heuristics.
    // If it's port 80 and the packet payload starts with 'GET ', 'POST' or 'HTTP.
    if (!(compress_flags & (IPZIP_COMPRESS_NO_DICT|IPZIP_COMPRESS_NO_LZ4)) &&
         port == 80 && source_len >= 44 && source_len <= IPZIP_MAX_DICT_COMPRESS_SIZE) {
      uint32 first = A32(source + 40);
      if (first == IPZIP_MKDWORD('G','E','T',' ') ||
          first == IPZIP_MKDWORD('P','O','S','T') ||
          first == IPZIP_MKDWORD('H','T','T','P')) {
        flags |= IPZIP_FLAG_CONTEXT_AWARE;
      }
    }

    goto FINAL_IP;
  } else if (protocol == 17) { // UDP
    flags |= IPZIP_FLAG_UDP;
    // Verify that the length field is proper.
    if (READ_WORD(source + 24) + 20 != source_len) UNABLE_TO_HANDLE();
    // Encode the dest port.
    *dest++ = (unsigned char)port;
    if (port >> 8) {
      *dest++ = (unsigned char)(port >> 8);
      flags |= IPZIP_FLAG_UDP_PORT;
    }
    // In UDP, checksum is optional.
    if ((source[20+6]|source[20+7]) == 0) {
      flags |= IPZIP_FLAG_UDP_NOSUM;
    } else if ((compress_flags&IPZIP_COMPRESS_NO_CKSUM) ||
               CalcTcpUdpChecksum(source, source_len) != 0xffffffff) {
      COPY_WORD(dest, &source[20+6]); dest += 2;
      flags |= IPZIP_FLAG_UDP_CKSUM;
    }
    n = 28;
FINAL_IP:
    // Encode TTL and DONT_FRAGMENT. TTL=0x80 seems to be a common case for outgoing packets,
    // while DONT_FRAGMENT is really rare for outgoing packets.
    {
      unsigned char ttl = source[8];
      if (sent_by_client && !(flags & 0xFFFFFF01)) {
        if ((source[6] & 0x40) != (flags & 0x40)) { flags |= IPZIP_MORE_FLAGS; goto TTLDEF; }
        if (ttl != 0x80) { flags |= IPZIP_FLAG_TTL_FRAG; *dest++ = ttl; }
      } else {
TTLDEF: flags |= (source[6] & 0x40) >> 4;           // IPZIP_FLAG_TTL_FRAG
        *dest++ = ttl;                              // TTL
      }
    }
  } else {
FALLBACK:
    flags = 0;
    n = 0;
    dest = dest_org;
  }
  // First attempt lz4 compression of payload. Otherwise memcpy if lz4 has no gain.
  {
    int dsize = source_len - n;
    if (!(compress_flags & IPZIP_COMPRESS_NO_LZ4)) {
      int csize = IpzipCompressBuffer(ipzip, source + n, dest, dsize, flags);
      if (csize >= dsize) goto MEMCPY;
      dest += csize;
      flags |= IPZIP_FLAG_LZ4;
    } else {
MEMCPY:
      memcpy(dest, source+n, dsize);
      dest += dsize;
    }
  }
  // Store the flags at the very end of the packet after the (possibly) compressed payload.
  if (flags & 0xffffff01) {
    *dest++ = (unsigned char)(flags >> 8);
    flags |= IPZIP_MORE_FLAGS;
  }
  *dest++ = (unsigned char)flags;
  return dest - dest_org;
}

// Returns 0 on failure. Will fail only on invalid input. Will never fail with
// data returned from IpzipCompress.
size_t IpzipDecompress(Ipzip *ipzip,
                       const unsigned char *source, size_t source_len,
                       unsigned char *dest, size_t dest_len,
                       unsigned char client_addr[4], int sent_by_client) {
  const unsigned char *source_end = source + source_len, *t;
  const unsigned char *dest_end = dest + dest_len;
  int flags, n, final_size, tcp_flags, port;
  unsigned char *w;
  if (source == source_end) return 0;
  flags = *--source_end;
  if (flags & IPZIP_MORE_FLAGS) {
    if (source == source_end) return 0;
    flags |= *--source_end << 8;
  }
  if ((flags & 0x7F) != 0) {
    if (source_end - source < 6) return 0;
    dest[0] = 0x45;                                        // Version/IHL
    dest[1] = (flags & IPZIP_FLAG_DSCP_ECN) ? *source++ : 0;// ESCN byte
    COPY_WORD(dest+4, source); source += 2;                // Identification
    dest[7] = 0x00;                                        // Fragmentation offset not used
    t = client_addr;
    if (flags & IPZIP_FLAG_WRONG_IP) {
      t = source;
      if ((source += 4) >= source_end) return 0;
    }
    COPY_DWORD(&dest[16 - sent_by_client * 4], t);         // Source IP Address
    t = client_addr;
    if (flags & IPZIP_FLAG_HIGHIPNEQ) {
      t = source;
      if ((source += 2) >= source_end) return 0;
    }
    w = &dest[12 + sent_by_client * 4];
    COPY_WORD(w, t);                                       // Destination IP Address high word
    if ((source_end - source) < 5) return 0;
    COPY_WORD(w + 2, source);                              // Destination IP Address low word
    COPY_WORD(&dest[22 - sent_by_client*2],  source + 2);  // Source port number
    source += 4;
    if (flags & IPZIP_FLAG_TCP) {
      dest[9] = 6; // Protocol TCP
      if (flags & IPZIP_FLAG_TCP_PORT_80) {
        port = (flags & 0x10) ? 443 : 80;
      } else {
        port = *source++;
        if (flags & 0x10) {
          if (source == source_end) return 0;
          port |= *source++ << 8;
        }
      }
      if (source_end - source < 10) return 0;
      COPY_QWORD(&dest[24], source);                       // Ack.nr, Seq.nr.
      source += 8;
      tcp_flags = 0x5010;
      if (flags & IPZIP_FLAG_TCP_FLAGS) {
        tcp_flags = *source++;
        tcp_flags = (tcp_flags & 0xF0) << 8 | (tcp_flags & 0x7) | (tcp_flags & 0x8) << 1;
      }
      tcp_flags |= (flags & IPZIP_FLAG_TCP_PUSH);
      WRITE_WORD(&dest[32], tcp_flags);                    // TCP flags
      if (source_end - source < 2) return 0;
      COPY_WORD(&dest[34], source); source += 2;           // Window Size
      if (flags & IPZIP_FLAG_TCP_CKSUM) {
        if (source_end - source < 2) return 0;
        COPY_WORD(&dest[36], source); source += 2;         // Checksum
      }
      WRITE_NATIVE_WORD(&dest[38], 0);                     // Urgent Ptr always zero.
      n = 40;
    } else if ((flags & 0x70) == IPZIP_FLAG_UDP) {
      dest[9] = 17;                                        // Protocol UDP
      port = *source++;
      if (flags & IPZIP_FLAG_UDP_PORT) {
        if (source == source_end) return 0;
        port |= *source++ << 8;
      }
      if (flags & IPZIP_FLAG_UDP_CKSUM) {
        if (source_end - source < 2) return 0;
        COPY_WORD(dest + 26, source); source += 2;         // Checksum
      }
      n = 28;
    } else {
      return 0;
    }
    WRITE_WORD(dest + 20 + sent_by_client*2, port);        // Destination port number
    // Don't fragment and TTL both share a bit.
    if (sent_by_client && !(flags & 1)) {
      dest[6] = (flags & IPZIP_FLAG_TCP);                  // DONT_FRAGMENT=1 for tcp else 0.
      if (!(flags & IPZIP_FLAG_TTL_FRAG))
        dest[8] = 0x80;                                    // TTL = 0x80
      else
        dest[8] = *source++;                               // TTL
    } else {
      dest[6] = (flags & IPZIP_FLAG_TTL_FRAG) << 4;        // Don't fragment
      dest[8] = *source++;                                 // TTL
    }
  } else {
    n = 0;
  }
  if (flags & IPZIP_FLAG_LZ4) {
    int rv = IpzipDecompressBuffer(ipzip, source, dest + n, source_end - source,
                                   dest_end - dest, flags);
    if (rv < 0) return 0;
    final_size = n + rv;
  } else {
    final_size = n + source_end - source;
    memcpy(dest + n, source, source_end - source);
  }
  if (n != 0) {
    WRITE_WORD(dest + 2, final_size);                      // Total Length of IP packet
    WRITE_NATIVE_WORD(dest + 10, 0);
    WRITE_NATIVE_WORD(dest + 10, CalcChecksum(0, dest, 20));  // IP Header checksum
    if (n == 40) {
      if (!(flags & IPZIP_FLAG_TCP_CKSUM)) {
        WRITE_NATIVE_WORD(dest + 36, 0);
        WRITE_NATIVE_WORD(dest + 36, CalcTcpUdpChecksum(dest, final_size));  // TCP checksum
      }
    } else {
      WRITE_WORD(dest + 24, final_size - 20);              // UDP Packet Size
      if (!(flags & IPZIP_FLAG_UDP_CKSUM)) {
        WRITE_NATIVE_WORD(dest + 26, 0);
        WRITE_NATIVE_WORD(dest + 26, (flags & IPZIP_FLAG_UDP_NOSUM) ? 0 : // UDP Checksum
                                     CalcTcpUdpChecksum(dest, final_size));
      }
    }
  }
  return final_size;
}
