using System;
using System.Text;

namespace CryptLink.SigningFramework {

    /// <summary>
    /// A immutable byte[] that can easily be hashed
    /// </summary>
    public class HashableBytes : Hashable {

        public HashableBytes() { }

        public HashableBytes(byte[] _Value) {
            if (_Value == null) {
                throw new ArgumentNullException("The provided byte[] can't be null");
            }

            Value = _Value;
        }

        public byte[] Value { get; protected set; }

        public override byte[] GetHashableData() {
            return Value;
        }

    }
}
