using System;
using System.Security.Cryptography;

namespace CryptLink.SigningFramework {
    public enum HashProvider {
        /// <summary>
        /// SHA2-256bits
        /// </summary>
        SHA256,

        /// <summary>
        /// SHA2-384bits
        /// </summary>
        SHA384,

        /// <summary>
        /// SHA2-512bits
        /// </summary>
        SHA512
    }

    public class HashOID : System.Attribute {
        private Oid _Value;

        public HashOID(Oid Value) {
            _Value = Value;
        }
    }

    public static class HashProviderExtentions {
        public static Oid GetOID(this HashProvider ForProvider) {
            return Oid.FromFriendlyName(ForProvider.ToString(), OidGroup.HashAlgorithm);
        }

        public static int GetProviderByteLength(this HashProvider ForProvider) {
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

        /// <summary>
        /// TODO: Analize the security/preformance tradeoff for this
        /// </summary>
        static HashAlgorithm[] hashAlgorithms = new HashAlgorithm[Enum.GetNames(typeof(HashProvider)).Length];

        /// <summary>
        /// Gets a HashAlgorithm from a HashProvider using a no-search static array
        /// </summary>
        [Obsolete("TODO: Refactor after dotnet core 2.1, (Use of CryptoConfig is discouraged)")]
        public static HashAlgorithm GetHashAlgorithm(this HashProvider Provider) {

            if (hashAlgorithms[(int)Provider] == null) {

                //var h = HashAlgorithm.Create(Provider.ToString());
                var h = (HashAlgorithm)CryptoConfig.CreateFromName(Provider.ToString());
                hashAlgorithms[(int)Provider] = h;
            }

            return hashAlgorithms[(int)Provider];
        }

        public static HashProvider GetCryptLinkHashProvider(this Oid oid) {
            switch (oid.FriendlyName) {
                case "sha256RSA":
                    return HashProvider.SHA256;
                case "sha384RSA":
                    return HashProvider.SHA384;
                case "sha512RSA":
                    return HashProvider.SHA512;
                default:
                    throw new NotImplementedException("No HashProvider implemented for Oid: '" + oid.FriendlyName + "'.");
            }
        }

        public static HashAlgorithmName GetHashAlgorithmName(this HashProvider Provider) {
            switch (Provider) {
                case HashProvider.SHA256:
                    return HashAlgorithmName.SHA256;
                case HashProvider.SHA384:
                    return HashAlgorithmName.SHA384;
                case HashProvider.SHA512:
                    return HashAlgorithmName.SHA512;
                default:
                    throw new NotImplementedException("Hash provider '" + Provider.ToString() + "' not implemented in GetHashAlgorithmName");
            }
        }

    }
}
