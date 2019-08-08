using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CryptLink.SigningFramework {
    public static class ByteExtentions {
        public static ComparableBytes ToComparable(this byte[] Bytes) {
            return new ComparableBytes(Bytes);
        }

        public static string ToB64String(this byte[] Bytes) {
            return Convert.ToBase64String(Bytes);
        }

        public static string ToB64String(this byte[] Bytes, bool UrlSafe, bool IncludePadding) {
            return Utility.EncodeBytes(Bytes, UrlSafe, IncludePadding);
        }

        public static Hash ComputeHash(this byte[] Bytes, HashProvider Provider) {
            return Hash.Compute(Bytes, Provider);
        }
        public static Hash ComputeHash(this byte[] Bytes, HashProvider Provider, Cert SigningCert) {
            return Hash.Compute(Bytes, Provider, SigningCert);
        }

        public static Hash ComputeHash(this byte[] Bytes, HashProvider Provider, X509Certificate2 SigningCert) {
            return Hash.Compute(Bytes, Provider, SigningCert);
        }

    }
}
