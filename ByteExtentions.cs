using System;
using System.Collections.Generic;
using System.Text;

namespace CryptLink.SigningFramework {
    public static class ByteExtentions {
        public static ComparableBytes ToComparable(this byte[] Bytes) {
            return new ComparableBytes(Bytes);
        }
    }
}
