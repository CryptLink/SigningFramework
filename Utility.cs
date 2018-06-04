using System;
using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace CryptLink.SigningFramework {
    public class Utility {

        public static string EncodeBytes(byte[] Bytes) {
            if (Bytes == null) {
                return null;
            }
            return Convert.ToBase64String(Bytes, 0, Bytes.Length);
        }

        public static byte[] DecodeBytes(string B64EncodedBytes) {
            if (string.IsNullOrWhiteSpace(B64EncodedBytes)) {
                return null;
            }

            try {
                Byte[] b = Convert.FromBase64String(B64EncodedBytes);
                return b;
            } catch (FormatException) {
                return null;
            }
        }

        public static bool AddCertToStore(Cert cert, StoreName st, StoreLocation sl) {
            try {
                X509Store store = new X509Store(st, sl);
                store.Open(OpenFlags.ReadWrite);
                store.Add(cert.X509Certificate);

                store.Close();
                return true;
            } catch {
                return false;
            }
        }

        public static X509Certificate2 GetCertFromStore(StoreName st, StoreLocation sl, string SerialNumber) {
            try {
                X509Store store = new X509Store(st, sl);
                store.Open(OpenFlags.ReadWrite);
                var foundCert = store.Certificates.Find(X509FindType.FindBySerialNumber, SerialNumber, true);

                store.Close();

                if (foundCert.Count > 0) {
                    return foundCert[0];
                } else if (foundCert.Count > 1) {
                    throw new IndexOutOfRangeException("More than one cert found for the seral number: " + SerialNumber.ToString());
                } else {
                    return null;
                }

            } catch {
                return null;
            }
        }

        /// <summary>
        /// A slightly more robust x509 cert verifier for quick testing of certs
        /// </summary>
        /// <param name="Cert">Certificate to verify</param>
        /// <param name="AllowUnknownCA">If true, Allows Unknown Certificate Authority</param>
        /// <param name="CheckRevocationStatus">If true the revocation status will not be checked, 
        /// generally revocation can't be checked for custom CAs are used since they don't run a revocation server</param>
        /// <param name="CustomCA">If provided, added to the ExtraStore for CA search</param>
        /// <param name="Intermediates">Other intermediate certs to include for checking the chain</param>
        /// <returns>True if valid</returns>
        public static bool VerifyCert(X509Certificate2 Cert, bool AllowUnknownCA, X509RevocationMode CheckRevocationMode,
            X509Certificate2 CustomCA, params X509Certificate2[] Intermediates) {

            X509Chain chain = new X509Chain();
            chain.ChainPolicy = new X509ChainPolicy();

            if (AllowUnknownCA) {
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            }

            chain.ChainPolicy.RevocationMode = CheckRevocationMode;

            if (CustomCA != null) {
                chain.ChainPolicy.ExtraStore.Add(CustomCA);
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.AllowUnknownCertificateAuthority;
            }

            if (Intermediates.Length > 0) {
                chain.ChainPolicy.ExtraStore.AddRange(Intermediates);
            }

            string log = "";
            try {
                var chainBuilt = chain.Build(Cert);
                log += (string.Format("Chain built: {0}. ", chainBuilt));

                if (chainBuilt == false) {
                    foreach (X509ChainStatus chainStatus in chain.ChainStatus) {
                        log += (string.Format("Chain error, status: {0}, Info: {1}. ", chainStatus.Status, chainStatus.StatusInformation));
                    }

                    return false;
                } else {

                    if (CustomCA != null) {
                        //check the CA manually to avoid the need to install it in the computer's root store
                        var chainCA = chain.ChainElements[chain.ChainElements.Count - 1];

                        if (chainCA.Certificate.Thumbprint == CustomCA.Thumbprint) {
                            return true;
                        } else {
                            log += "Chain CA thumbprint was not the same as the provided CA";
                            return false;
                        }
                    } else {
                        return true;
                    }

                }

            } catch (Exception ex) {
                log += (ex.ToString());
                return false;
            }


        }

    }

}
