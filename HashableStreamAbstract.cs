using System;
using System.IO;
using System.Text;

namespace CryptLink.SigningFramework {

    /// <summary>
    /// A immutable byte[] that can easily be hashed
    /// </summary>
    public abstract class HashableStreamAbstract : IHashableStream {

        public Hash ComputedHash { get; set; }

        public bool Verify() {
            string n = null;
            return ComputedHash.Verify(GetHashableStream(), out n);
        }

        public bool Verify(out string Reason) {
            return ComputedHash.Verify(GetHashableStream(), out Reason);
        }

        public bool Verify(Cert SigningPublicCert) {
            string n = null;
            return ComputedHash.Verify(GetHashableStream(), out n, SigningPublicCert);
        }

        /// <summary>
        /// Verifies the hash and signature of an object
        /// </summary>
        /// <param name="SigningPublicCert"></param>
        /// <returns>Returns TRUE if the hash and signature verify correctly</returns>
        public bool Verify(Cert SigningPublicCert, out string Reason) {
            return ComputedHash.Verify(GetHashableStream(), out Reason, SigningPublicCert);
        }

        public Stream GetHashableStream() {
            _value.Position = 0;
            return _value;
        }

        public void ComputeHash(HashProvider Provider, Cert SigningCert) {
            ComputedHash = Hash.Compute(GetHashableStream(), Provider, SigningCert);
        }

        public void ComputeHash(HashProvider Provider) {
            ComputeHash(Provider, null);
        }

        Stream _value;
        public Stream Value {
            get { return _value; }
            set {
                if (value != _value) {
                    this.ComputedHash = null;
                    _value = value;
                }
            }
        }



    }
}
