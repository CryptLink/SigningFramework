using System;
using System.Security.Cryptography;
using System.Text;

namespace CryptLink.SigningFramework {

    /// <summary>
    /// 
    /// </summary>
    public class Hash : ComparableBytesAbstract {
        public HashProvider? Provider { get; set; }

        public override byte[] Bytes { get; set; }

        public byte[] SignatureBytes { get; set; }

        public byte[] SignatureCertHash { get; set; }

        /// <summary>
        /// The number of bytes hashed to get this result
        /// </summary>
        public int SourceByteLength { get; private set; }

        static HashAlgorithm[] hashAlgorithms = new HashAlgorithm[Enum.GetNames(typeof(HashProvider)).Length];

        public Hash() { }

        /// <summary>
        /// Creates a immutable hash object with the specified hash bytes. NOTE: this does not COMPUTE a hash, use Hash.Compute
        /// </summary>
        /// <param name="HashedBytes">The bytes to copy into this hash</param>
        /// <param name="_Provider"></param>
        private Hash(byte[] HashedBytes, HashProvider _Provider, int _SourceByteLength) {

            if (HashedBytes.Length == GetProviderByteLength(_Provider)) {
                Bytes = HashedBytes;
                Provider = _Provider;
                SourceByteLength = _SourceByteLength + GetProviderByteLength(_Provider);
            } else {
                throw new ArgumentException("The provided bytes are not the expected length, should be: "
                    + GetProviderByteLength(_Provider) +
                    " but was actually: " + HashedBytes.Length);
            }            
        }
        
        /// <summary>
        /// Copies the bytes from a b64 string to a new Hash (does not compute a hash)
        /// </summary>
        public static Hash FromB64(string Base64String, HashProvider _Provider, int SourceBytesLength) {
            var bytes = Utility.DecodeBytes(Base64String);
            return FromComputedBytes(bytes, _Provider, SourceBytesLength);
        }

        /// <summary>
        /// Copies a pre-computed hash bytes in a Hash object
        /// </summary>
        /// <param name="PreComputedHashBytes"></param>
        /// <param name="_Provider"></param>
        /// <returns></returns>
        public static Hash FromComputedBytes(byte[] PreComputedHashBytes, HashProvider _Provider, int SourceBytesLength) {
            if (PreComputedHashBytes.Length == GetProviderByteLength(_Provider)) {
                return new Hash(PreComputedHashBytes, _Provider, SourceBytesLength);
            } else {
                throw new ArgumentException("Provided bytes were not the expected length for this hash type");
            }
        }

        /// <summary>
        /// Gets the number of bytes for the current hash provider
        /// </summary>
        public int HashByteLength(bool ZeroIndexed) {
            if (!Provider.HasValue) {
                throw new NullReferenceException("Provider is not set to a value");
            }

            return GetProviderByteLength(Provider.Value);
        }

        /// <summary>
        /// Checks if the hash is structurally valid, does not validate the actual hash
        /// </summary>
        public bool HashLengthValid(int? SigningCertLength = null) {
            var r = "";
            return HashLengthValid(out r, SigningCertLength);
        }

        /// <summary>
        /// Checks if the hash is structurally valid, does not validate the actual hash
        /// </summary>
        public bool HashLengthValid(out string Reasion, int? SigningCertLength = null) {
            if (!Provider.HasValue) {
                throw new NullReferenceException("Provider is not set to a value");
            }

            var providerLength = GetProviderByteLength(Provider.Value);

            if (this.Bytes == null) {
                Reasion = "No hash bytes";
                return false;
            } else if (this.Bytes.Length != providerLength) {
                Reasion = "Hash is the wrong length";
                return false;
            }

            if (this.SignatureBytes != null) {
                if (SigningCertLength == null) {
                    Reasion = "The hash is signed, but no signing cert was provided.";
                    return false;
                } else if(this.SignatureBytes.Length != (SigningCertLength.Value / 8)) {
                    Reasion = "Hash signature is the wrong length";
                    return false;
                }
            }

            //all tests passes
            Reasion = null;
            return true;
        }
        
        /// <summary>
        /// Verifies this hash is correct for the data provided, optionally checks the signature as well
        /// </summary>
        /// <param name="DataBytes">Data to hash</param>
        /// <param name="SigningCert">Certificate to check the signature against</param>
        /// <returns></returns>
        public bool Verify(byte[] DataBytes, out string Reasion, Cert SigningCert = null) {
            if (!Provider.HasValue) {
                throw new NullReferenceException("Provider is not set to a value");
            }

            if (HashLengthValid(out Reasion, SigningCert.PublicKey.Key.KeySize) == false) {
                return false;
            }

            if (this.SignatureBytes != null) {
                if (SigningCert != null) {
                    RSACryptoServiceProvider csp = (RSACryptoServiceProvider)SigningCert.PublicKey.Key;
                    return csp.VerifyHash(this.Bytes, GetOIDForProvider(this.Provider.Value), this.SignatureBytes);
                } else {
                    //must have the signing cert and the signature bytes
                    Reasion = "The hash is signed, but no signing cert was provided";
                    return false;
                }
            } else {
                var computed = Compute(DataBytes, this.Provider.Value, null);
                if (this.Bytes != computed.Bytes) {
                    Reasion = "Computed hash does not match the provided hash";
                    return false;
                }
            }

            Reasion = null;
            return true;
        }

        public static int GetProviderByteLength(HashProvider ForProvider) {
            switch (ForProvider) {
                case HashProvider.SHA256:
                    return 32;
                case HashProvider.SHA384:
                    return 48;
                case HashProvider.SHA512:
                    return 64;
                default:
                    throw new NotImplementedException("Hash provider '" + ForProvider.ToString() + "' not implemented in GetHashByteLength");
            }
        }

        public static string GetOIDForProvider(HashProvider Provider) {
            return CryptoConfig.MapNameToOID(Provider.ToString());
        }

        public static HashProvider GetProviderForOID(Oid Provider) {
            HashProvider parsedProvider;

            if (Enum.TryParse(Provider.FriendlyName, out parsedProvider)) {
                return parsedProvider;
            }

            throw new NotImplementedException($"OID Name: {Provider.FriendlyName} is not supported.");
        }

        /// <summary>
        /// Computes a hash from a string
        /// </summary>
        /// <param name="FromString">The string to hash</param>
        /// <param name="Provider">The provider to hash with</param>
        /// <param name="SigningCert">Optional cert to sign with</param>
        /// <returns>A new Hash object</returns>
        public static Hash Compute(string FromString, HashProvider Provider, Cert SigningCert = null) {
            UnicodeEncoding UE = new UnicodeEncoding();
            return Compute(UE.GetBytes(FromString), Provider, SigningCert);
        }

        /// <summary>
        /// Computes the hash from a byte[] and sets the HashProvider
        /// If a cert with a private key is provided the hash will also be signed
        /// </summary>
        /// <param name="FromBytes">Bytes to compute the hash from</param>
        /// <param name="Provider">The crypto provider to compute the hash with</param>
        /// <param name="SigningCert">Optional cert to sign with</param>
        public static Hash Compute(byte[] FromBytes, HashProvider Provider, Cert SigningCert = null) {

            if (FromBytes == null) {
                return null;
            }

            HashAlgorithm hashAlgo = GetHashAlgorithm(Provider);
            var hash = new Hash(hashAlgo.ComputeHash(FromBytes), Provider, FromBytes.Length);

            if (SigningCert != null && SigningCert.HasPrivateKey) {
                SigningCert.SignHash(hash, Provider);
            }

            return hash;
        }

        /// <summary>
        /// Gets a HashAlgorithm from a HashProvider using a no-search static array
        /// </summary>
        private static HashAlgorithm GetHashAlgorithm(HashProvider Provider) {
            
            if (hashAlgorithms[(int)Provider] == null) {
                var h = HashAlgorithm.Create(Provider.ToString());
                hashAlgorithms[(int)Provider] = h;            
            }

            return hashAlgorithms[(int)Provider];
        }

        /// <summary>
        /// Generates a new hash by re-hashing the current hash bytes
        /// Useful for making a new re-producible hash for distributing in a ConsistentHash table, not signable 
        /// </summary>
        public Hash Rehash() {
            if (!Provider.HasValue) {
                throw new NullReferenceException("Provider is not set to a value");
            }

            return Hash.Compute(Bytes, Provider.Value, null);
        }

    }

}
