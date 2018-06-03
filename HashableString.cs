using System;
using System.Text;

namespace CryptLink.SigningFramework {

    /// <summary>
    /// A immutable string that can easily be hashed
    /// </summary>
    public class HashableString : Hashable {

        public HashableString() { }

        public HashableString(string _Value) {
            if (_Value == null) {
                throw new ArgumentNullException("The provided string can't be null");
            }

            Value = _Value;
        }
        
        public string Value { get; protected set; }

        public override byte[] GetHashableData() {
            return Encoding.ASCII.GetBytes(Value);
        }

    }
}
