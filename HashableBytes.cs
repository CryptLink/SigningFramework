using System;
using System.Text;

namespace CryptLink.SigningFramework {

    /// <summary>
    /// A immutable byte[] that can easily be hashed
    /// </summary>
    public class HashableBytes : Hashable {

        public HashableBytes() { }

        /// <summary>
        /// Creates a hashable bytes, does not compute the hash
        /// </summary>
        public HashableBytes(byte[] _Value) {
            if (_Value == null) {
                throw new ArgumentNullException("The provided byte[] can't be null");
            }

            Value = _Value;
        }

        /// <summary>
        /// Creates a hashable bytes, computes the hash immediately
        /// </summary>
        public HashableBytes(byte[] _Value, HashProvider Provider) {
            if (_Value == null) {
                throw new ArgumentNullException("The provided byte[] can't be null");
            }

            Value = _Value;
            this.ComputeHash(Provider);
        }

        /// <summary>
        /// Creates a hashable bytes, computes the hash and signs immediately
        /// </summary>
        public HashableBytes(byte[] _Value, HashProvider Provider, Cert SigningCert) {
            if (_Value == null) {
                throw new ArgumentNullException("The provided byte[] can't be null");
            }

            Value = _Value;
            this.ComputeHash(Provider, SigningCert);
        }

        byte[] _value;
        public byte[] Value {
            get { return _value; }
            set {
                if (value != _value) {
                    this.ComputedHash = null;
                    _value = value;
                }
            }
        }

        public override byte[] GetHashableData() {
            return Value;
        }

    }
}
