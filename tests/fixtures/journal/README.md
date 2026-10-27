# Journal export fixtures (P4.2)

The journal tests generate `journalctl -o export` byte streams from the
definitions below; no real journal data is tracked. `\n` is a literal newline
and `\xNN` a single byte.

## Binary, repeated, and tab-containing entry

```
__CURSOR=s=739ad463348b4ceca5a9e69c95a3c93f;i=4ece7;b=6c7c6013a26343b29e964691ff25d04c\n
__REALTIME_TIMESTAMP=1342540861416409\n
__MONOTONIC_TIMESTAMP=21415215982\n
_BOOT_ID=6c7c6013a26343b29e964691ff25d04c\n
_HOSTNAME=host-a\n
MESSAGE=first message\n
MESSAGE=second message\n
BINARY\n<64-bit little-endian 9><666f6f0a6261720007>\n
TAB_VALUE=a<TAB>b\n
\n
```

Expected: one observation whose raw pairs keep both `MESSAGE` values in order
and `BINARY` as `{"binary_hex":"666f6f0a6261720007"}` (the embedded newline is
data, not a field separator). The event summary is the first `MESSAGE`, the
host is `host-a`, the realtime instant is `1342540861.416409000`, and the
monotonic time is stored with clock domain
`boot:6c7c6013a26343b29e964691ff25d04c`.

## Truncated length

```
__REALTIME_TIMESTAMP=1000000\n
_BOOT_ID=6c7c6013a26343b29e964691ff25d04c\n
MESSAGE=complete entry\n
\n
BROKEN\n<100 as little-endian u64>abc<EOF>
```

Expected: the complete entry is kept; the second entry produces
`truncated_field` and is not stored.

## Boot scoping

Entries with `__MONOTONIC_TIMESTAMP` but different `_BOOT_ID` values produce
distinct `boot:<id>` clock domains. `compare_boot_times` returns `None` across
them and an order only within one boot. An entry with monotonic time and no
`__REALTIME_TIMESTAMP` stays `unresolved` with no chosen timeline instant.
