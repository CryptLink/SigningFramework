using System;
using System.Collections.Generic;
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
    }
}
