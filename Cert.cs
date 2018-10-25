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

        private X509Certificate2 _x509Certificate;
        public X509Certificate2 GetX509Certificate() {
            return _x509Certificate;
        }

        public void SetX509Certificate(X509Certificate2 _Cert) {
            _x509Certificate = _Cert;
        }

        public string Thumbprint => GetX509Certificate().Thumbprint;

        public PublicKey PublicKey => GetX509Certificate().PublicKey;

        public bool HasPrivateKey => GetX509Certificate().HasPrivateKey;

        public int KeyLength => GetX509Certificate().PublicKey.Key.KeySize;

        /// <summary>
        /// For deserializing
        /// </summary>
        public Cert() { }

        public Cert(X509Certificate2 Certificate) {
            this.SetX509Certificate(Certificate);
            Provider = Certificate.SignatureAlgorithm.GetCryptLinkHashProvider();
            ComputeHash(Provider);
            SeralizeCertificate();
        }

        public Cert(X509Certificate2 Certificate, SecureString EncryptionPassword) {
            this.SetX509Certificate(Certificate);
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
            if (GetX509Certificate() == null) {
                throw new NullReferenceException("Certificate is null, it should be set and have a valid decryption password");
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

                SetX509Certificate(new X509Certificate2(Utility.DecodeBytes(CertificateBase64), EncryptionPassword));
            }

            if (ProtectedStoragePath != null) {
                throw new NotImplementedException("Todo: implement OS storage");
            }

            if (!PasswordEncrypt && ProtectedStoragePath == null) {
                SetX509Certificate(new X509Certificate2(Utility.DecodeBytes(CertificateBase64)));
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

                CertificateBase64 = Utility.EncodeBytes(GetX509Certificate().Export(X509ContentType.Pkcs12, EncryptionPassword));
            }

            if (ProtectedStoragePath != null) {
                throw new NotImplementedException("Todo: implement OS storage");
            }

            if (!PasswordEncrypt && ProtectedStoragePath == null) {
                var exportBytes = GetX509Certificate().Export(X509ContentType.Pkcs12);
                CertificateBase64 = Utility.EncodeBytes(exportBytes);
                exportBytes = null;
            }

        }

        /// <summary>
        /// Re-parses an X509Certificate2 to only contain the public key
        /// </summary>
        public Cert RemovePrivateKey() {
            if (GetX509Certificate() == null) {
                return null;
            } else {
                return new Cert(new X509Certificate2(GetX509Certificate().RawData));
            }

        }

        public override byte[] GetHashableData() {
            if (GetX509Certificate() == null) {
                //possible improvement: get from web request
                throw new NullReferenceException("Certificate not set");
            } else {
                return GetX509Certificate().PublicKey.EncodedKeyValue.RawData;
            }
        }

        /// <summary>
        /// Use this cert to verify a hash
        /// </summary>
        /// <param name="Hash">The hash to verify</param>
        /// <param name="Provider">The provider to use</param>
        public bool VerifyHash(Hash Hash, HashProvider Provider) {
            using (var rsa = RSA.Create()) {
                rsa.ImportParameters(GetX509Certificate().GetRSAPublicKey().ExportParameters(false));
                return rsa.VerifyData(Hash.Bytes, Hash.SignatureBytes, Provider.GetHashAlgorithmName(), RSASignaturePadding.Pkcs1);
            }
        }

    }
}
