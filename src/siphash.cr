# Copyright 2015 Sérgio 'wherd' Leal. All rights reserved.
# Use of this source code is governed by a MIT-style
# license that can be found in the LICENSE file.

require "./siphash/*"

# Implementation of SipHash-2-4, a fast short-input PRF
#
# ```
# require "siphash"
#
# hash = SipHash::digest(0x12345678, 0x12345678, "my string")
# ```
module SipHash

    def self.digest(k0, k1, str)
        digest(k0.to_u64, k1.to_u64, str)
    end

    def self.digest(k0 : UInt64, k1 : UInt64, str)
        h = Hash.new k0, k1
        h.digest str
    end

    struct Hash
        @v0 : UInt64
        @v1 : UInt64
        @v2 : UInt64
        @v3 : UInt64

        def initialize(k0 : UInt64, k1 : UInt64)
            @v0 = k0 ^ 0x736f6d6570736575_u64
            @v1 = k1 ^ 0x646f72616e646f6d_u64
            @v2 = k0 ^ 0x6c7967656e657261_u64
            @v3 = k1 ^ 0x7465646279746573_u64
        end

        # Returns the 64-bit SipHash-2-4
        def digest(msg : String)
            digest Slice.new(msg.to_unsafe, msg.bytesize)
        end

        def digest(msg : Slice(UInt8) | Array(UInt8))
            len = msg.size
            iter = len / 8

            iter.times do |i|
                off = i * 8

                m = msg[off].to_u64 |
                    msg[off+1].to_u64 << 8 |
                    msg[off+2].to_u64 << 16 |
                    msg[off+3].to_u64 << 24 |
                    msg[off+4].to_u64 << 32 |
                    msg[off+5].to_u64 << 40 |
                    msg[off+6].to_u64 << 48 |
                    msg[off+7].to_u64 << 56

                @v3 ^= m
                2.times { compress }
                @v0 ^= m
            end

            # Last block
            m = last_block msg, len, iter
            @v3 ^= m

            2.times { compress }
            @v0 ^= m

            # Finalize
            @v2 ^= 0xff
            4.times { compress }

            # Digest
            @v0 ^ @v1 ^ @v2 ^ @v3
        end

        private def compress
            @v0 += @v1
            @v1 = @v1<<13 | @v1>>(64-13)
            @v1 ^= @v0
            @v0 = @v0<<32 | @v0>>(64-32)

            @v2 += @v3
            @v3 = @v3<<16 | @v3>>(64-16)
            @v3 ^= @v2

            @v0 += @v3
            @v3 = @v3<<21 | @v3>>(64-21)
            @v3 ^= @v0

            @v2 += @v1
            @v1 = @v1<<17 | @v1>>(64-17)
            @v1 ^= @v2

            @v2 = @v2<<32 | @v2>>(64-32)
        end

        private def last_block(msg, len, iter)
            last = len.to_u64 << 56

            r = len % 8
            off = iter * 8

            last |= (msg[off+6].to_u64 << 48) if r > 6
            last |= (msg[off+5].to_u64 << 40) if r > 5
            last |= (msg[off+4].to_u64 << 32) if r > 4
            last |= (msg[off+3].to_u64 << 24) if r > 3
            last |= (msg[off+2].to_u64 << 16) if r > 2
            last |= (msg[off+1].to_u64 << 8) if r > 1
            last |= msg[off].to_u64 if r > 0

            last
        end
    end
end
