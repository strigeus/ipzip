ipzip
=====

IpZip - TCP/IP Packet Compressor with LZ4 support

WHAT IS IPZIP?
==============
IpZip is a compressor optimized for compressing TCP/IP packets. It combines
several different ideas. The compression is completely stateless, so prior
packets are not needed to decompress future packets, i.e. packet loss is not
an issue. IpZip is designed to compress small packets around ~1500 bytes
large. In all cases (even for invalid packets or random input data) will the
decompressed result be bit-identical to the input. If compression is not
possible, the overhead of using IpZip is exactly one byte.
IpZip recomputes the TCP/IP checksums to avoid storing them in the packet,
so IpZip packets need to be transported over a reliable transport mechanism.
This uses quite some CPU and can optionally be disabled.

One use case for IpZip is to compress traffic over a VPN link.

The following ideas are employed:
1) IP/TCP/UDP Header Compression exploits redundancy in the packet headers
   and tries to represent them in a more compact form. This roughly halves
   the packet header size on average, from 40 bytes to around 20 bytes for
   TCP, or even less for UDP. To facilitate this process, IpZip needs
   knowledge of the IP address of one endpoint, as well as the direction the
   packet is traveling. This information is not required, but if provided,
   gives better compression. LZ77 based compressors don't do a good job on
   TCP/IP headers as they do not contain a lot of redundant information.
2) The LZ4 algorithm is used to compress the rest of the packet payload.
   This is a very fast algorithm that still gives reasonably good compress
   ratios, although for packet sizes as small as 1500 bytes, it does not
   have a lot of possibilities for compression, so it doesn't make wonders.
3) To compensate for the slim opportunities for redundancy in small packets,
   the LZ4 compressor can optionally use a static dictionary. This
   dictionary is seeded with a bunch of common strings seen in HTTP traffic,
   and facilitates compression of HTTP headers.

BENCHMARK
=========
This benchmark is run on a single core on an Intel Core i7 860.
HeaderCompression + LZ4 + Dictionary:
  Compress:   442.423798 MB/s.
  Decompress: 1839.497314 MB/s.
  Result:     239984490 => 219007105 (91.258850%, saved 20977385 bytes)
HeaderCompression + LZ4:
  Compress:   451.330933 MB/s.
  Decompress: 1920.994507 MB/s.
  Result:     239984490 => 224107177 (93.384033%, saved 15877313 bytes)
HeaderCompression only:
  Compress:   2816.371094 MB/s.
  Decompress: 2071.843018 MB/s.
  Result:     239984490 => 232643052 (96.940865%, saved 7341438 bytes)
HeaderCompression only. TCP checksum optimization disabled:
  Compress:   5623.430664 MB/s.
  Decompress: 3150.432373 MB/s.
  Result:     239984490 => 233802332 (97.423935%, saved 6182158 bytes)
LZ4 only:
  Compress:   457.206451 MB/s.
  Decompress: 7425.835938 MB/s.
  Result:     239984490 => 231889959 (96.627060%, saved 8094531 bytes)