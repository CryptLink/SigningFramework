using System;
using System.IO;
using System.Text;

namespace CryptLink.SigningFramework {

    /// <summary>
    /// A immutable byte[] that can easily be hashed
    /// </summary>
    public class HashableStream : HashableStreamAbstract {

        public HashableStream() { }

        /// <summary>
        /// Creates a hashable stream
        /// </summary>
        public HashableStream(Stream _Value) {
            if (_Value == null || _Value.CanRead == false) {
                throw new ArgumentNullException("The provided stream can't be null, and must be readable");
            }

            Value = _Value;
        }

        /// <summary>
        /// Creates a hashable stream, computes the hash immediately
        /// </summary>
        public HashableStream(Stream _Value, HashProvider Provider) {
            if (_Value == null || _Value.CanRead == false) {
                throw new ArgumentNullException("The provided stream can't be null, and must be readable");
            }

            Value = _Value;
            this.ComputeHash(Provider);
        }

        /// <summary>
        /// Creates a hashable bytes, computes the hash and signs immediately
        /// </summary>
        public HashableStream(Stream _Value, HashProvider Provider, Cert SigningCert) {
            if (_Value == null || !_Value.CanRead) {
                throw new ArgumentNullException("The provided stream can't be null, and must be readable");
            }

            Value = _Value;
            this.ComputeHash(Provider, SigningCert);
        }

    }
}
