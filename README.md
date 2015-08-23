# siphash

Crystal implementation of SipHash-2-4

[![Build Status](https://travis-ci.org/wherd/siphash.svg)](https://travis-ci.org/wherd/siphash)

## Projectile

```crystal
deps do
  github "wherd/siphash"
end
```

## Usage

```crystal
require "siphash"

# SipHash.digest(key_0 UInt64, Key_1 UInt64, message String)
h = SipHash.digest(0, 0, "hello world")
```
