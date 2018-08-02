using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Text;
using static CryptLink.SigningFramework.Utility;

namespace CryptLink.SigningFrameworkTests
{

    [TestFixture()]
    class UtilityTests {

        [Test(), Category("Utility")]
        public void B64Padding() {

            byte[][] testBytes = { 
                new byte[] { 240, 255 },
                new byte[] { 0, 255 },
                new byte[] { 32, 231, 55 },
                new byte[] { 255, 240, 62, 0 },
                new byte[] { 255, 255, 0, 0, 234 },
                new byte[] { 7, 8, 9, 123, 0, 0 },
                new byte[] { 74, 52, 51, 254, 240, 62, 0 },
                new byte[] { 255, 240, 62, 0, 0, 45, 0, 0 },
            };

            foreach (var testValue in testBytes) {
                //standard
                var smallStandard = EncodeBytes(testValue, false, true);
                Assert.AreEqual(testValue, DecodeBytes(smallStandard, true));
                Assert.AreEqual(testValue, DecodeBytes(smallStandard, false));

                //standard no pad
                var smallNoPad = EncodeBytes(testValue, false, false);
                if (smallStandard.EndsWith('=')) {
                    Assert.AreNotEqual(testValue, DecodeBytes(smallNoPad, true));
                } else {
                    Assert.AreEqual(testValue, DecodeBytes(smallNoPad, true));
                }
                Assert.AreEqual(testValue, DecodeBytes(smallNoPad, false));

                //url safe
                var smallUrlSafe = EncodeBytes(testValue, true, true);
                Assert.AreEqual(testValue, DecodeBytes(smallUrlSafe, true));
                Assert.AreEqual(testValue, DecodeBytes(smallUrlSafe, false));

                //url safe no pad
                var smallUrlSafeNoPad = EncodeBytes(testValue, true, false);
                if (smallStandard.EndsWith('=')) {
                    Assert.AreNotEqual(testValue, DecodeBytes(smallUrlSafeNoPad, true));
                } else {
                    Assert.AreEqual(testValue, DecodeBytes(smallUrlSafeNoPad, true));
                }
                Assert.AreEqual(testValue, DecodeBytes(smallUrlSafeNoPad, false));
            }

        }

    }
}
