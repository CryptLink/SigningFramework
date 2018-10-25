## 1.3.3
Adding: ByteExtentions - byte[].ToComparable()
Updating: readme
Adding: Simple ComprableByte unit test

## 1.3.2
Bugfix: hash create methods to respect the provided ComputedDate

## 1.3.0
Adjusting the value set/get in HashableString and HashableByte

## 1.2.0
Adjusting the creation signatures of `Hash` to take a `long?` length, and `DateTimeOffset?`

``` C#
Hash(byte[] HashedBytes, HashProvider _Provider, long? _SourceByteLength, DateTimeOffset? _ComputedDate)
```