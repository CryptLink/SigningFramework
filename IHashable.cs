namespace CryptLink.SigningFramework {

    /// <summary>
    /// Interface to be implemented by any object that supports hashing by the framework
    /// </summary>
    public interface IHashable {

        /// <summary>
        /// Gets the hash of this object using a specified provider, and signs it with a certificate (if provided)
        /// </summary>
        void ComputeHash(HashProvider Provider, Cert SigningCert);

        bool Verify();

        bool Verify(out string Reason);

        bool Verify(Cert SigningPublicCert);

        bool Verify(Cert SigningPublicCert, out string Reason);

        /// <summary>
        /// The computed hash of this object
        /// </summary>
        Hash ComputedHash { get; set; }

    }
}
