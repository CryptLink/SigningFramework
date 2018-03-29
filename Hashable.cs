using System;

namespace CryptLink.HashFramework {
    /// <summary>
    /// The abstract class that enables easy to use hashing and hashed based comparison
    /// </summary>
    public abstract class Hashable : IHashable {

        /// <summary>
        /// A byte array of data to be hashed
        /// </summary>
        public abstract byte[] GetHashableData();
        

        public byte[] ComputedHashBytes() {
            if (ComputedHash != null) {
                return ComputedHash.Bytes;
            } else {
                throw new NullReferenceException("No hash exists");
            }
        }

        /// <summary>
        /// The computed hash for this object, will be null until ComputeHash() is called
        /// </summary>
        public Hash ComputedHash { get; set; }

        /// <summary>
        /// Compute a hash for this object and optionally signs it
        /// </summary>
        /// <param name="Provider">The hash provider to use</param>
        /// <param name="SigningCert">If provided the cert to sign the hash with</param>
        public void ComputeHash(Hash.HashProvider Provider, Cert SigningCert = null) {
            ComputedHash = Hash.Compute(GetHashableData(), Provider, SigningCert);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public bool Verify() {
            string n = null;
            return ComputedHash.Verify(GetHashableData(), out n);
        }

        public bool Verify(out string Reason) {
            return ComputedHash.Verify(GetHashableData(), out Reason);
        }

        public bool Verify(Cert SigningPublicCert) {
            string n = null;
            return ComputedHash.Verify(GetHashableData(), out n, SigningPublicCert);
        }

        /// <summary>
        /// Verifies the hash and signature of an object
        /// </summary>
        /// <param name="SigningPublicCert"></param>
        /// <returns>Returns TRUE if the hash and signature verify correctly</returns>
        public bool Verify(Cert SigningPublicCert, out string Reason) {
            return ComputedHash.Verify(GetHashableData(), out Reason, SigningPublicCert);
        }

    }
}
