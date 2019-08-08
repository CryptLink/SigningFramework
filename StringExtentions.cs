using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CryptLink.SigningFramework {
    public static class StringExtentions {

        public static byte[] ToBytes(this string Base64) {
            return Utility.DecodeBytes(Base64);
        }

        public static Hash ComputeHash(this string StringValue, HashProvider Provider) {
            return Hash.Compute(StringValue, Provider);
        }
        public static Hash ComputeHash(this string StringValue, HashProvider Provider, Cert SigningCert) {
            return Hash.Compute(StringValue, Provider, SigningCert);
        }

        public static Hash ComputeHash(this string StringValue, HashProvider Provider, X509Certificate2 SigningCert) {
            return Hash.Compute(StringValue, Provider, SigningCert);
        }

    }
}
