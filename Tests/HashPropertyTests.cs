using CryptLink.SigningFramework;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.Text;

namespace CryptLink.SigningFrameworkTests
{
    [TestFixture]
    public class HashPropertyTests {

        [Test]
        public void TestGetPropertyData() {
            var testObject = new TestObject();
            var testObjectB64 = Utility.EncodeBytes(testObject.GetPropertyBinary());
            var expectedB64 = "AAEAAAD/////AQAAAAAAAAAGAQAAABNSdW50aW1lUHJvcGVydHlJbmZvCwABAAAA/////wEAAAAAAAAABAEAAAAMU3lzdGVtLkludDMyAQAAAAdtX3ZhbHVlAAhA4gEACwABAAAA/////wEAAAAAAAAABgEAAAATUnVudGltZVByb3BlcnR5SW5mbwsAAQAAAP////8BAAAAAAAAAAQBAAAAD1N5c3RlbS5EYXRlVGltZQIAAAAFdGlja3MIZGF0ZURhdGEAAAkQgOpwJQCZ1QiA6nAlAJnVCAsAAQAAAP////8BAAAAAAAAAAYBAAAAE1J1bnRpbWVQcm9wZXJ0eUluZm8LAAEAAAD/////AQAAAAAAAAAEAQAAABVTeXN0ZW0uRGF0ZVRpbWVPZmZzZXQCAAAACERhdGVUaW1lDU9mZnNldE1pbnV0ZXMAAA0HgFiaRL2Y1QjgAQsAAQAAAP////8BAAAAAAAAAAYBAAAAE1J1bnRpbWVQcm9wZXJ0eUluZm8LAAEAAAD/////AQAAAAAAAAAEAQAAAA5TeXN0ZW0uRGVjaW1hbAQAAAAFZmxhZ3MCaGkCbG8DbWlkAAAAAAgICAgAAAMAAAAAAEDiAQAAAAAACwABAAAA/////wEAAAAAAAAABgEAAAATUnVudGltZVByb3BlcnR5SW5mbwsAAQAAAP////8BAAAAAAAAAAYBAAAABFRFU1QL";

            Assert.AreEqual(testObjectB64, expectedB64, "Object bytes are as expected");

            testObject.IntUnhashed = -1;
            var testObjectB64_2 = Utility.EncodeBytes(testObject.GetPropertyBinary());

            Assert.AreEqual(testObjectB64, testObjectB64_2, "Change of property not marked with [HashProperty] does not change result from GetPropertyBinary()");

            testObject.IntHashed = -1;
            var testObjectB64_3 = Utility.EncodeBytes(testObject.GetPropertyBinary());
            Assert.AreNotEqual(testObjectB64, testObjectB64_3, "Change of property marked with [HashProperty] does change result from GetPropertyBinary()");
        }

        [Test]
        public void TestHashProperty() {
            var testObject = new TestObject();
            var testObjectBytes = testObject.GetPropertyBinary();

            testObject.ComputeHash(HashProvider.SHA256);
            var testHash1 = testObject.ComputedHash;
            var expectedHash = Hash.FromB64("OuJ0jb8i/mUf3bcB4PqBl84pA9CdreAqO9qFf4l60Ak=", HashProvider.SHA256, testObjectBytes.Length);
            Assert.AreEqual(expectedHash, testHash1);

            testObject.IntUnhashed = -1;
            testObject.ComputeHash(HashProvider.SHA256);
            var testHash2 = testObject.ComputedHash;
            Assert.AreEqual(testHash1, testHash2, "Change of property not marked with [HashProperty] does not change the hash");

            testObject.IntHashed = -1;
            testObject.ComputeHash(HashProvider.SHA256);
            var testHash3 = testObject.ComputedHash;
            Assert.AreEqual(expectedHash, testHash3, "Change of property not marked with [HashProperty] does not change the hash");

        }
    }

    public class TestObject : Hashable {
        [HashProperty]
        public int IntHashed { get; set; } = 0b11110001001000000;
        public int IntUnhashed { get; set; } = 0b10011111101111110001;

        [HashProperty]
        public DateTime DateTimeHashed { get; set; } = 
            new DateTime(0x7E2, 0x4, 0x3, 0x1, 0xD, 0x2D);

        [HashProperty]
        public DateTimeOffset DateTimeOffsetHashed { get; set; } = 
            new DateTimeOffset(
                new DateTime(0b11111100010, 0b100, 0b11, 0b1, 0b1111, 0b1), 
                new TimeSpan(0b1000, 0b0, 0b0)
            );

        [HashProperty]
        public decimal DecimalHashed { get; set; } = 123.456m;

        [HashProperty]
        public string StringHashed { get; set; } = "TEST";

        public override byte[] GetHashableData() {
            return GetPropertyBinary();
        }
    }
}
