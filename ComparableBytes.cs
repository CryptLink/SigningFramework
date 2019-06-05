using System;

namespace CryptLink.SigningFramework {

    /// <summary>
    /// A comparable (and sortable) byte[]
    /// </summary>
    public class ComparableBytes : IComparable {
        
        public byte[] Bytes { get; set; }

        public ComparableBytes() { }

        public ComparableBytes(byte[] FromBytes) {
            Bytes = FromBytes;
        }

        /// <summary>
        /// Returns a base B64 representation of the hash
        /// </summary>
        /// <returns></returns>
        public override string ToString() {
            return Convert.ToBase64String(Bytes);
        }

        /// <summary>
        /// Returns a Base 64 representation of the hash
        /// </summary>
        /// <returns></returns>
        public string ToB64String() {
            return Convert.ToBase64String(Bytes);
        }

        public static int Compare(ComparableBytes Left, ComparableBytes Right) {

			if (ReferenceEquals(Right, null) && ReferenceEquals(Left, null)) {
				return 0;
			} else if (ReferenceEquals(Right, null)) {
                return -1;
            } else if (ReferenceEquals(Left, null)) {
                return 1;
            }

            return Compare(Left.Bytes, Right.Bytes);
        }

        public static int Compare(byte[] Left, ComparableBytes Right) {
            return Compare(Left, Right.Bytes);
        }

        public static int Compare(ComparableBytes Left, byte[] Right) {
            return Compare(Left.Bytes, Right);
        }

        /// <summary>
        /// Compares two byte arrays of any length
        /// </summary>
        /// <returns>1, 0 or -1</returns>
        public static int Compare(byte[] Left, byte[] Right) {
            int compareLength;

            //the hashes could be a different length, that's okay, we'll only compare the shared bits
            compareLength = Math.Min(Left.Length, Right.Length);

            if (BitConverter.IsLittleEndian) {
                //read in Little Endian order
                for (int i = 0; i < compareLength; i++) {
                    if (Left[i] > Right[i]) {
                        return 1;
                    } else if (Left[i] < Right[i]) {
                        return -1;
                    }
                }
            } else {
                //read in Big Endian order
                for (int i = compareLength; i > 0; i--) {
                    if (Left[i] > Right[i]) {
                        return 1;
                    } else if (Left[i] < Right[i]) {
                        return -1;
                    }
                }
            }

            //All the shared bits are the same, so return the longer hash
            if (Left.Length > Right.Length) {
                return 1;
            } else if (Left.Length < Right.Length) {
                return -1;
            }

            //Same bits and length, arrays are equal
            return 0;
        }

        #region // ICompariable methods

        public int CompareTo(byte[] Bytes) {
            return Compare(this, Bytes);
        }

        public int CompareTo(ComparableBytes HashObject) {
            return Compare(this.Bytes, HashObject.Bytes);
        }

        public int CompareTo(object obj) {
            if (obj == null) {
                return 1;
            } else if (obj is Hash) {
                return CompareTo((Hash)obj);
            } else if (obj is byte[]) {
                return CompareTo((byte[])obj);
            }

            return 1;
        }

        public static explicit operator byte[] (ComparableBytes b) {
            return b.Bytes;
        }

        /// <summary>
        /// Compare to object, will always return false for any object that is not Hash or byte[] 
        /// (Required for IComparable)
        /// </summary>
        public override bool Equals(object obj) {
            if (obj is Hash) {
                return CompareTo((Hash)obj) == 0;
            } else if (obj is byte[]) {
                return CompareTo((byte[])obj) == 0;
            }

            return false;
        }

        public bool Equals(Hash HashObject) {
            return CompareTo(HashObject) == 0;
        }

        #endregion 

		/// <summary>
		/// Deprecated and implemented for compatibility only, returns a truncated version of the bytes (first 4 bytes).
        /// (Needed for OverrideGetHashCodeOnOverridingEquals)
        /// </summary>
		[Obsolete("Deprecated and implemented for compatibility only, returns a truncated version of the hash bytes (first 4).")]
		public override int GetHashCode() {
            return BitConverter.ToInt32(Bytes, 0);
        }

        #region // All common operators needed for boolean operations

        public static implicit operator ComparableBytes(byte[] instance) {
            return new ComparableBytes(instance);
        }

        public static bool operator ==(ComparableBytes Left, ComparableBytes Right) {
            return Compare(Left, Right) == 0;
        }

        public static bool operator !=(ComparableBytes Left, ComparableBytes Right) {
            return Compare(Left, Right) != 0;
        }

        public static bool operator >(ComparableBytes Left, ComparableBytes Right) {
            return Compare(Left, Right) > 0;
        }

        public static bool operator <(ComparableBytes Left, ComparableBytes Right) {
            return Compare(Left, Right) < 0;
        }

        public static bool operator >=(ComparableBytes Left, ComparableBytes Right) {
            return Compare(Left, Right) >= 0;
        }

        public static bool operator <=(ComparableBytes Left, ComparableBytes Right) {
            return Compare(Left, Right) <= 0;
        }

        #endregion

    }
}
