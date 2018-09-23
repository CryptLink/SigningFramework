using System;
using System.Text;

namespace CryptLink.SigningFramework {

    /// <summary>
    /// A string that can easily be hashed
    /// </summary>
    public class HashableString : Hashable {

        public HashableString() { }

        /// <summary>
        /// Creates a hashable string, does not compute the value
        /// </summary>
        public HashableString(string _Value) {
            if (_Value == null) {
                throw new ArgumentNullException("The provided string can't be null");
            }

            Value = _Value;
        }

        /// <summary>
        /// Creates a hashable string and computes the hash immediately 
        /// </summary>
        public HashableString(string _Value, HashProvider Provider) {
            if (_Value == null) {
                throw new ArgumentNullException("The provided string can't be null");
            }

            Value = _Value;
            this.ComputeHash(Provider);
        }

        /// <summary>
        /// Creates a hashable string and computes the hash and signs immediately 
        /// </summary>
        public HashableString(string _Value, HashProvider Provider, Cert SigningCert) {
            if (_Value == null) {
                throw new ArgumentNullException("The provided string can't be null");
            }

            Value = _Value;
            this.ComputeHash(Provider, SigningCert);
        }


        string _value;
        public string Value {
            get { return _value; }
            set {
                if (value != _value) {
                    this.ComputedHash = null;
                    _value = value;
                }
            }
        }

        public override byte[] GetHashableData() {
            return Encoding.ASCII.GetBytes(Value);
        }

    }
}
