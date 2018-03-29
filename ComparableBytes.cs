namespace CryptLink.HashFramework {

    /// <summary>
    /// A minimal class for implementing ComparableBytesAbstract. Lowest level type for storing bytes that need to be compared and sorted.
    /// </summary>
    class ComparableBytes : ComparableBytesAbstract {
        public override byte[] Bytes { get; set; }

        public ComparableBytes() { }
        public ComparableBytes(byte[] FromBytes) {
            Bytes = FromBytes;
        }
    }
}
