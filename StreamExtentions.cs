using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace CryptLink.SigningFramework {
    public static class StreamExtentions {

        public static Hash ComputeHash(this Stream StreamValue, HashProvider Provider) {
            return Hash.Compute(StreamValue, Provider);
        }
        public static Hash ComputeHash(this Stream StreamValue, HashProvider Provider, Cert SigningCert) {
            return Hash.Compute(StreamValue, Provider, SigningCert);
        }

        public static Hash ComputeHash(this Stream StreamValue, HashProvider Provider, X509Certificate2 SigningCert) {
            return Hash.Compute(StreamValue, Provider, SigningCert);
        }

    }
}
