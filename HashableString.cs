using System;
using System.Text;

namespace CryptLink.SigningFramework {

    /// <summary>
    /// A string that can easily be hashed
    /// </summary>
    public class HashableString : Hashable {

        public HashableString() { }

        public HashableString(string _Value) {
            if (_Value == null) {
                throw new ArgumentNullException("The provided string can't be null");
            }

            Value = _Value;
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
