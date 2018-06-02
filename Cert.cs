using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security;
using System.Runtime.Serialization;
using static CryptLink.SigningFramework.Hash;

namespace CryptLink.SigningFramework {


    /// <summary>
    /// A wrapper for x509Certificate2 that provides easy signing, saving and loading
    /// </summary>
    public class Cert : Hashable {

        /// <summary>
        /// The base 64 encoded bytes that comprise the certificate
        /// </summary>
        public string CertificateBase64 { get; set; }

        /// <summary>
        /// The path to where the cert is stored in the OS's secure storage
        /// </summary>
        public string ProtectedStoragePath { get; set; }

        /// <summary>
        /// If true, the b64 version of the certificate will be encrypted with the specified password
        /// </summary>
        public bool PasswordEncrypt { get; set; }

        /// <summary>
        /// The hash provider for this object
        /// </summary>
        public HashProvider Provider { get; set; }

        /// <summary>
        /// The password to encrypt/decrypt the certificate with
        /// </summary>
        public SecureString EncryptionPassword { private get; set; }

        public X509Certificate2 X509Certificate { get; set; }

        public string Thumbprint => X509Certificate.Thumbprint;

        public PublicKey PublicKey => X509Certificate.PublicKey;

        public bool HasPrivateKey => X509Certificate.HasPrivateKey;

        public int KeyLength => X509Certificate.PublicKey.Key.KeySize;

        /// <summary>
        /// For deserializing
        /// </summary>
        public Cert() { }

        public Cert(X509Certificate2 Certificate) {
            this.X509Certificate = Certificate;
            Provider = Certificate.SignatureAlgorithm.GetCryptLinkHashProvider();
            ComputeHash(Provider);
            SeralizeCertificate();
        }

        public Cert(X509Certificate2 Certificate, SecureString EncryptionPassword) {
            this.X509Certificate = Certificate;
            this.EncryptionPassword = EncryptionPassword;
            this.PasswordEncrypt = true;
            Provider = Certificate.SignatureAlgorithm.GetCryptLinkHashProvider();
            ComputeHash(Provider);
            SeralizeCertificate();
        }

        public static Cert LoadFromPfx(string PfxPath, string PfxPassword) {
            X509Certificate2Collection collection = new X509Certificate2Collection();
            //X509KeyStorageFlags.PersistKeySet
            collection.Import(PfxPath, PfxPassword, X509KeyStorageFlags.Exportable);

            if (collection.Count == 1) {
                foreach (var cert in collection) {
                    return new Cert(cert);
                }
            }

            throw new InvalidOperationException($"The certificate had {collection.Count} certificates, it should contain 1");
        }

        public bool CheckCertificate() {
            if (X509Certificate == null) {
                throw new NullReferenceException("The certificate does not exist, make sure it is accessible, the decryption password is correct");
            }

            return true;
        }

        /// <summary>
        /// Loads the certificate using a SecureString for decryption
        /// This function is only needed when the certificate is encrypted with a password.
        /// </summary>
        public void LoadCertificate(SecureString EncryptionPassword, HashProvider Provider) {
            this.EncryptionPassword = EncryptionPassword;
            this.Provider = Provider;
            LoadCertificate(Provider);
        }

        /// <summary>
        /// Loads an unencrypted cert
        /// </summary>
        private void LoadCertificate(HashProvider Provider) {
            if (PasswordEncrypt) {
                if (EncryptionPassword == null) {
                    throw new Exception("No decryption password was specified, can't encrypt the certificate");
                }

                X509Certificate = new X509Certificate2(Utility.DecodeBytes(CertificateBase64), EncryptionPassword);
            }

            if (ProtectedStoragePath != null) {
                throw new NotImplementedException("Todo: implement OS storage");
            }

            if (!PasswordEncrypt && ProtectedStoragePath == null) {
                X509Certificate = new X509Certificate2(Utility.DecodeBytes(CertificateBase64));
            }

            ComputeHash(Provider);

        }

        [OnDeserialized]
        internal void OnDeseralized(StreamingContext context) {
            //after deserialization, load the certificate
            if (PasswordEncrypt == false) {
                LoadCertificate(Provider);
            }
        }

        [OnSerializing]
        internal void OnSerializing(StreamingContext context) {
            //before serialize, encrypt the certificate
            if (PasswordEncrypt == true) {
                SeralizeCertificate();
            }
        }
        
        public void SeralizeCertificate() {
            CheckCertificate();

            if (PasswordEncrypt) {
                if (EncryptionPassword == null) {
                    throw new Exception("No decryption password was specified, can't encrypt the certificate");
                }

                CertificateBase64 = Utility.EncodeBytes(X509Certificate.Export(X509ContentType.Pkcs12, EncryptionPassword));
            }

            if (ProtectedStoragePath != null) {
                throw new NotImplementedException("Todo: implement OS storage");
            }

            if (!PasswordEncrypt && ProtectedStoragePath == null) {
                var exportBytes = X509Certificate.Export(X509ContentType.Pkcs12);
                CertificateBase64 = Utility.EncodeBytes(exportBytes);
                exportBytes = null;
            }

        }

        /// <summary>
        /// Re-parses an X509Certificate2 to only contain the public key
        /// </summary>
        public Cert RemovePrivateKey() {
            if (X509Certificate == null) {
                return null;
            } else {
                return new Cert(new X509Certificate2(X509Certificate.RawData));
            }

        }

        public override byte[] GetHashableData() {
            if (X509Certificate == null) {
                //possible improvement: get from web request
                throw new NullReferenceException("Certificate not set");
            } else {
                return X509Certificate.PublicKey.EncodedKeyValue.RawData;
            }
        }

        /// <summary>
        /// Use this cert to sign a hash
        /// </summary>
        /// <param name="Hash">The hash to sign</param>
        /// <param name="Provider">The provider to use</param>
        public void SignHash(Hash Hash, HashProvider Provider) {
            if (X509Certificate.HasPrivateKey && Hash.Bytes != null) {
                //var csp = RSA.Create();//(RSACryptoServiceProvider)X509Certificate.PrivateKey;
                //Hash.SignatureBytes = csp.SignHash(Hash.Bytes, Provider.GetOID().Value);
                //Hash.SignatureCertHash = this.ComputedHash.Bytes;

                using (var rsa = RSA.Create()) {
                    RSAParameters rp = new RSAParameters();
                    rsa.ImportParameters(X509Certificate.GetRSAPrivateKey().ExportParameters(true));

                    Hash.SignatureBytes = rsa.SignData(Hash.Bytes, Provider.GetHashAlgorithmName(), RSASignaturePadding.Pkcs1);
                    Hash.SignatureCertHash = this.ComputedHash.Bytes;
                }
            } else {
                throw new NullReferenceException("No private key");
            }
        }

        /// <summary>
        /// Use this cert to verify a hash
        /// </summary>
        /// <param name="Hash">The hash to verify</param>
        /// <param name="Provider">The provider to use</param>
        public bool VerifyHash(Hash Hash, HashProvider Provider) {
            using (var rsa = RSA.Create()) {
                RSAParameters rp = new RSAParameters();
                rsa.ImportParameters(X509Certificate.GetRSAPublicKey().ExportParameters(false));
                return rsa.VerifyData(Hash.Bytes, Hash.SignatureBytes, Provider.GetHashAlgorithmName(), RSASignaturePadding.Pkcs1);
            }
        }

    }
}
