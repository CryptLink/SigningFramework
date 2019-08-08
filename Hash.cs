using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CryptLink.SigningFramework {

    /// <summary>
    /// A implementation of ComparableBytes
    /// </summary>
    public class Hash : ComparableBytes {

        HashProvider? _provider;
        public HashProvider? Provider {
            get => _provider;
            set {
                if (_provider == null) {
                    _provider = value;
                } else {
                    throw new FieldAccessException("Provider can only be set once.");
                }
            }
        }

        byte[] _signatureBytes;
        public byte[] SignatureBytes {
            get =>_signatureBytes;
            set {
                if (_signatureBytes == null) {
                    _signatureBytes = value;
                } else {
                    throw new FieldAccessException("SignatureBytes can only be set once.");
                }
            }
        }

        byte[] _signatureCertHash;
        public byte[] SignatureCertHash {
            get => _signatureCertHash;
            set {
                if (_signatureCertHash == null) {
                    _signatureCertHash = value;
                } else {
                    throw new FieldAccessException("SignatureCertHash can only be set once.");
                }
            }
        }

        DateTimeOffset? _computedDate;
        public DateTimeOffset? ComputedDate {
            get => _computedDate;
            set {
                if (_computedDate == null) {
                    _computedDate = value;
                } else {
                    throw new FieldAccessException("ComputedDate can only be set once.");
                }
            }
        }

        /// <summary>
        /// The number of bytes hashed to get this result
        /// </summary>
        long? _sourceByteLength;
        public long? SourceByteLength {
            get => _sourceByteLength;
            set {
                if (_sourceByteLength == null) {
                    _sourceByteLength = value;
                } else {
                    throw new FieldAccessException("SourceByteLength can only be set once.");
                }
            }
        }
        
        public Hash() { }

        /// <summary>
        /// Creates a immutable hash object with the specified hash bytes. NOTE: this does not COMPUTE a hash, use Hash.Compute
        /// </summary>
        /// <param name="HashedBytes">The bytes to copy into this hash</param>
        /// <param name="_Provider"></param>
        private Hash(byte[] HashedBytes, HashProvider _Provider, long? _SourceByteLength, DateTimeOffset? _ComputedDate) {

            if (HashedBytes.Length == _Provider.GetProviderByteLength()) {
                Bytes = HashedBytes;
                Provider = _Provider;
                SourceByteLength = _SourceByteLength + HashedBytes.Length;
                ComputedDate = _ComputedDate;
            } else {
                throw new ArgumentException("The provided bytes are not the expected length, should be: "
                    + _Provider.GetProviderByteLength() +
                    " but was actually: " + HashedBytes.Length);
            }            
        }

        /// <summary>
        /// Copies the bytes from a b64 string to a new Hash (does not compute a hash)
        /// Accepts standard b64 or 'base64url' with URL and Filename Safe Alphabet (RFC 4648 §5, Table 2, value 62 = '-', 63 = '_') padding optional
        /// </summary>
        public static Hash FromB64(string Base64String, HashProvider _Provider, long? _SourceByteLength, DateTimeOffset? _ComputedDate) {
            var bytes = Utility.DecodeBytes(Base64String);
            return FromComputedBytes(bytes, _Provider, _SourceByteLength, _ComputedDate);
        }

        /// <summary>
        /// Copies a pre-computed hash bytes in a Hash object
        /// </summary>
        /// <param name="PreComputedHashBytes"></param>
        /// <param name="_Provider"></param>
        /// <returns></returns>
        public static Hash FromComputedBytes(byte[] PreComputedHashBytes, HashProvider _Provider, long? _SourceByteLength, DateTimeOffset? _ComputedDate) {
            if (PreComputedHashBytes == null) {
                throw new ArgumentNullException("The PreComputedHashBytes argument was null, can't create a Hash.");
            } 

            if (PreComputedHashBytes.Length == _Provider.GetProviderByteLength()) {
                return new Hash(PreComputedHashBytes, _Provider, _SourceByteLength, _ComputedDate);
            } else {
                throw new ArgumentException("Provided bytes were not the expected length for this hash type");
            }
        }

        /// <summary>
        /// Gets the number of bytes for the current hash provider
        /// </summary>
        public int HashByteLength() {
            if (!Provider.HasValue) {
                throw new NullReferenceException("Provider is not set to a value");
            }

            return Provider.Value.GetProviderByteLength();
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

            var providerLength = Provider.Value.GetProviderByteLength();

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
        /// Sign this hash with a certificate
        /// </summary>
        /// <param name="Hash">The hash to sign</param>
        /// <param name="Provider">The provider to use</param>
        public void Sign(HashProvider Provider, Cert Certificate) {
            if (Certificate.HasPrivateKey && Bytes != null) {
                using (var rsa = RSA.Create()) {
                    rsa.ImportParameters(Certificate.X509Certificate.GetRSAPrivateKey().ExportParameters(true));

                    SignatureBytes = rsa.SignData(Bytes, Provider.GetHashAlgorithmName(), RSASignaturePadding.Pkcs1);
                    SignatureCertHash = Certificate.ComputedHash.Bytes;
                }
            } else {
                throw new NullReferenceException("No private key");
            }
        }

        /// <summary>
        /// Verifies this hash is correct for the data provided, optionally checks the signature as well
        /// </summary>
        /// <param name="DataStream">Stream to hash</param>
        /// <param name="SigningCert">Certificate to check the signature against</param>
        /// <returns></returns>
        public bool Verify(Stream DataStream, out string Reasion, Cert SigningCert = null) {
            if (!Provider.HasValue) {
                throw new NullReferenceException("Provider is not set to a value");
            }

            if (HashLengthValid(out Reasion, SigningCert?.PublicKey?.Key?.KeySize) == false) {
                return false;
            }

            if (this.SignatureBytes != null) {
                if (SigningCert != null) {
                    if (!SigningCert.VerifyHash(this, this.Provider.Value)) {
                        Reasion = "The hash signature is invalid";
                        return false;
                    }
                } else {
                    //must have the signing cert and the signature bytes
                    Reasion = "The hash is signed, but no signing cert was provided";
                    return false;
                }
            }

            //actually check the hash
            var computed = Compute(DataStream, this.Provider.Value, default(Cert));

            if (this != computed) {
                Reasion = "Computed hash does not match the provided hash";
                return false;
            }

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

            if (HashLengthValid(out Reasion, SigningCert?.PublicKey?.Key?.KeySize) == false) {
                return false;
            }

            if (this.SignatureBytes != null) {
                if (SigningCert != null) {
                    if (!SigningCert.VerifyHash(this, this.Provider.Value)) {
                        Reasion = "The hash signature is invalid";
                        return false;
                    } 
                } else {
                    //must have the signing cert and the signature bytes
                    Reasion = "The hash is signed, but no signing cert was provided";
                    return false;
                }
            } 

            //actually check the hash
            var computed = Compute(DataBytes, this.Provider.Value, default(Cert));

            if (this != computed) {
                Reasion = "Computed hash does not match the provided hash";
                return false;
            }

            Reasion = null;
            return true;
        }

        /// <summary>
        /// Computes a hash from a stream
        /// </summary>
        /// <param name="FromStream">The stream to hash</param>
        /// <param name="Provider">The provider to hash with</param>
        /// <returns>A new Hash object</returns>
        public static Hash Compute(Stream FromStream, HashProvider Provider) {
            return Compute(FromStream, Provider, default(Cert));
        }

        /// <summary>
        /// Computes a hash from a stream
        /// </summary>
        /// <param name="FromStream">The stream to hash</param>
        /// <param name="Provider">The provider to hash with</param>
        /// <param name="SigningCert">The certificate to sign the hash with</param>
        /// <returns>A new Hash object</returns>
        public static Hash Compute(Stream FromStream, HashProvider Provider, X509Certificate2 SigningCert) {
            return Compute(FromStream, Provider, new Cert(SigningCert));
        }

        /// <summary>
        /// Computes a hash from a stream
        /// </summary>
        /// <param name="FromStream">The stream to hash</param>
        /// <param name="Provider">The provider to hash with</param>
        /// <param name="SigningCert">The certificate to sign the hash with</param>
        /// <returns>A new Hash object</returns>
        public static Hash Compute(Stream FromStream, HashProvider Provider, Cert SigningCert = null) {
            if (!FromStream.CanRead || !FromStream.CanSeek) {
                return null;
            }

            HashAlgorithm hashAlgo = Provider.GetHashAlgorithm();
            var hash = new Hash(hashAlgo.ComputeHash(FromStream), Provider, FromStream.Length, DateTimeOffset.Now);

            if (SigningCert != null && SigningCert.HasPrivateKey) {
                hash.Sign(Provider, SigningCert);
            }

            return hash;
        }

        /// <summary>
        /// Computes a hash from a string
        /// </summary>
        /// <param name="FromString">The string to hash</param>
        /// <param name="Provider">The provider to hash with</param>
        /// <returns>A new Hash object</returns>
        public static Hash Compute(string FromString, HashProvider Provider) {
            UTF8Encoding UE = new UTF8Encoding();
            return Compute(UE.GetBytes(FromString), Provider, default(Cert));
        }



        /// <summary>
        /// Computes a hash from a string
        /// </summary>
        /// <param name="FromString">The string to hash</param>
        /// <param name="Provider">The provider to hash with</param>
        /// <param name="SigningCert">Optional cert to sign with</param>
        /// <returns>A new Hash object</returns>
        public static Hash Compute(string FromString, HashProvider Provider, Cert SigningCert) {
            UnicodeEncoding UE = new UnicodeEncoding();
            return Compute(UE.GetBytes(FromString), Provider, SigningCert);
        }

        /// <summary>
        /// Computes a hash from a string
        /// </summary>
        /// <param name="FromString">The string to hash</param>
        /// <param name="Provider">The provider to hash with</param>
        /// <param name="SigningCert">Optional cert to sign with</param>
        /// <returns>A new Hash object</returns>
        public static Hash Compute(string FromString, HashProvider Provider, X509Certificate2 SigningCert) {
            UnicodeEncoding UE = new UnicodeEncoding();
            return Compute(UE.GetBytes(FromString), Provider, SigningCert);
        }
        
        /// <summary>
        /// Computes a hash from a string
        /// </summary>
        /// <param name="FromString">The string to hash</param>
        /// <param name="Provider">The provider to hash with</param>
        /// <returns>A new Hash object</returns>
        public static Hash Compute(byte[] FromBytes, HashProvider Provider) {
            UnicodeEncoding UE = new UnicodeEncoding();
            return Compute(FromBytes, Provider, default(Cert));
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

            HashAlgorithm hashAlgo = Provider.GetHashAlgorithm();
            var hash = new Hash(hashAlgo.ComputeHash(FromBytes), Provider, FromBytes.Length, DateTimeOffset.Now);

            if (SigningCert != null && SigningCert.HasPrivateKey) {
                hash.Sign(Provider, SigningCert);
            }

            return hash;
        }

        /// <summary>
        /// Computes the hash from a byte[] and sets the HashProvider
        /// If a cert with a private key is provided the hash will also be signed
        /// </summary>
        /// <param name="FromBytes">Bytes to compute the hash from</param>
        /// <param name="Provider">The crypto provider to compute the hash with</param>
        /// <param name="SigningCert">Optional cert to sign with</param>
        public static Hash Compute(byte[] FromBytes, HashProvider Provider, X509Certificate2 SigningCert = null) {
            if (SigningCert == null) {
                return Compute(FromBytes, Provider, default(Cert));
            } else {
                return Compute(FromBytes, Provider, new Cert(SigningCert));
            }
        }

    }

}
