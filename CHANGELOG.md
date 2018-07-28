## 1.2.0

Adjusting the creation signatures of `Hash` to take a `long?` length, and `DateTimeOffset?`

``` C#
Hash(byte[] HashedBytes, HashProvider _Provider, long? _SourceByteLength, DateTimeOffset? _ComputedDate)
```