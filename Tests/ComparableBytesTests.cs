using CryptLink.SigningFramework;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Text;

namespace CryptLink.SigningFrameworkTests {
    [TestFixture()]
    public class ComparableBytesTests {

        [Test(), Category("Hash Compare")]
        public void BinaryToBinaryOperators() {

            var tempGuid = Guid.NewGuid().ToString();
            var h1 = Hash.Compute(tempGuid, HashProvider.SHA256);
            var h2 = Hash.Compute(tempGuid, HashProvider.SHA256);
            var h3 = Hash.Compute(tempGuid.ToUpper(), HashProvider.SHA256);

            byte[] max = new byte[h1.HashByteLength()];
            byte[] min = new byte[h1.HashByteLength()];

            for (var i = 0; i < max.Length; i++) {
                max[i] = 255;
                min[i] = 0;
            }

            //All operators (hash to binary)
            Assert.AreEqual(ComparableBytes.Compare(h1.Bytes, h2.Bytes), 0);
            Assert.AreNotEqual(ComparableBytes.Compare(h1.Bytes, h3.Bytes), 0);

            Assert.AreEqual(ComparableBytes.Compare(h1.Bytes, min), 1);
            Assert.AreEqual(ComparableBytes.Compare(h3.Bytes, min), 1);

            Assert.AreEqual(ComparableBytes.Compare(h1.Bytes, max), -1);
            Assert.AreEqual(ComparableBytes.Compare(h3.Bytes, max), -1);

        }

        [Test(), Category("Hash Compare")]
        public void ComparableBytesTest() {

            byte[] bytesA = { 1, 2, 3 };
            byte[] bytesB = { 1, 2, 3 };

            // Standard compare (by reference)
            if (bytesA == bytesB) {
                // Evaluates as false (A and B are different objects)
                Assert.Fail();
            }

            // using CryptLink.SigningFramework;
            if (bytesA.ToComparable() == bytesB.ToComparable()) {
                // Evaluates as true (A and B have the same byte values)
            } else {
                Assert.Fail();
            }

            // Using the ComparableBytes Wrapper
            var cBytesA = new ComparableBytes(bytesA);
            var cBytesB = new ComparableBytes(bytesB);

            if (cBytesA == cBytesB) {
                // Evaluates as true (A and B have the same byte values)
            } else {
                Assert.Fail();
            }

        }


    }
}
