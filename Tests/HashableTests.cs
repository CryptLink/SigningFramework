using CryptLink.SigningFramework;
using NUnit.Framework;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace CryptLinkTests {
    [TestFixture]
    public class HashableTests {

        [Test, Category("Hashing")]
        public void HashableIsHashable() {
            Assert.False(this is IHashableBytes, "This test's type should not derive from the Hashable type");
            Assert.False(new Hash() is IHashableBytes, "A Hash should derive from the Hashable type");
            Assert.True(new HashableString(Guid.NewGuid().ToString()) is IHashableBytes, "A HashableString should derive from the Hashable type");
        }

        [Test, Category("Hashing"), Category("Serialization")]
        public void HashableStringSerializeDeserialize() {

            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {
                var h1 = new HashableString(Guid.NewGuid().ToString());
                h1.ComputeHash(provider);
                var h1s = Newtonsoft.Json.JsonConvert.SerializeObject(h1);
                var h1d = Newtonsoft.Json.JsonConvert.DeserializeObject<HashableString>(h1s);

                //verify before recomputing
                Assert.IsTrue(h1.Verify());
                Assert.IsTrue(h1d.Verify());

                //check that the hash (and other fields) have not changed
                Assert.AreEqual(h1.ComputedHash, h1d.ComputedHash);
                Assert.AreEqual(h1.ComputedHash.ComputedDate, h1d.ComputedHash.ComputedDate);
                Assert.AreEqual(h1.ComputedHash.Bytes, h1d.ComputedHash.Bytes);
                Assert.AreEqual(h1.ComputedHash.HashByteLength(), h1d.ComputedHash.HashByteLength());
                Assert.AreEqual(h1.ComputedHash.Provider, h1d.ComputedHash.Provider);
                Assert.AreEqual(h1.ComputedHash.SourceByteLength, h1d.ComputedHash.SourceByteLength);
                Assert.AreEqual(h1.Value, h1d.Value);

                //verify after recomputing
                h1.ComputeHash(provider);
                h1d.ComputeHash(provider);
                Assert.IsTrue(h1.Verify());
                Assert.IsTrue(h1d.Verify());

                //check that the hash has not changed
                Assert.AreEqual(h1.ComputedHash, h1d.ComputedHash);
                Assert.AreEqual(h1.Value, h1d.Value);
            }
        }

        [Test, Category("Hashing"), Category("Serialization")]
        public void HashableBytesSerializeDeserialize() {

            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {
                var h1 = new HashableBytes(Guid.NewGuid().ToByteArray());
                h1.ComputeHash(provider);
                var h1s = Newtonsoft.Json.JsonConvert.SerializeObject(h1);
                var h1d = Newtonsoft.Json.JsonConvert.DeserializeObject<HashableBytes>(h1s);

                //verify before recomputing
                Assert.IsTrue(h1.Verify());
                Assert.IsTrue(h1d.Verify());

                //check that the hash has not changed
                Assert.AreEqual(h1.ComputedHash, h1d.ComputedHash);
                Assert.AreEqual(h1.Value, h1d.Value);

                //verify after recomputing
                h1.ComputeHash(provider);
                h1d.ComputeHash(provider);
                Assert.IsTrue(h1.Verify());
                Assert.IsTrue(h1d.Verify());

                //check that the hash has not changed
                Assert.AreEqual(h1.ComputedHash, h1d.ComputedHash);
                Assert.AreEqual(h1.Value, h1d.Value);
            }
        }

        [Test, Category("Hashing")]
        public void HashableStreamHashes() {

            var precomputedHashes = new Dictionary<HashProvider, string>() {
                { HashProvider.SHA256, @"QSz5LmQc4pbDAgZV0T7cfRW6vYHojRcdYIe/E/peFTY=" },
                { HashProvider.SHA384, @"mOMV/0r+ZC+qHvgrYnM7d5kGdsLjH5bNW75gEGwldFy5JEdJ2dctt9+aKBkX0lLV" },
                { HashProvider.SHA512, @"xl48gTfq6r+CxVxneqx9k3NGw0px6ubRdSnJUj/oR5MyabKlFC4FZwM2xBq0NkvM6lTOeQCGhZV0ET0EN11JZw==" }
            };

            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {
                byte[] byteArray = Encoding.ASCII.GetBytes("edb0f9cb-37a5-4c37-b8f7-7242e54bff34");
                MemoryStream stream = new MemoryStream(byteArray);

                var h = new HashableStream(stream, provider);
                h.ComputeHash(provider);

                Assert.True(precomputedHashes.ContainsKey(provider), "The stored test hash dictionary has a comparison Hash, and same as HashableString");

                var precomputedTestHash = precomputedHashes[provider];
                var computedHashString = h.ComputedHash.ToString();

                Assert.AreEqual(computedHashString, precomputedTestHash, "Computed and stored hash differ");
            }
        }

        [Test, Category("Hashing")]
        public void HashableFile() {

            var precomputedHashes = new Dictionary<HashProvider, string>() {
                { HashProvider.SHA256, @"7zVoltYfxNG3135m1sAy0gHa1FAnfPX8f6/7gXj0bhQ=" },
                { HashProvider.SHA384, @"k+a9v4mKAMpp0c+QvyIcF/vo7E7bsg+4D0VRWxCPzlMYOhqO+LsOTLrjqT2HcXWL" },
                { HashProvider.SHA512, @"+NLCPuBL1SKOVctXmBP6jI58yY2KEm38iZWNMJA/SnUAh03AR0p6M4u9VsElKnrJnSxfPdtj1BuLGm9sYH4A3Q==" }
            };

            var testFilePath = "HashableFileTest.txt";

            File.WriteAllText(testFilePath, "DE85CD8E-87CB-45AE-A07E-F7863B9065B7");

            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {
                var hf = new HashableFile(testFilePath);
                hf.ComputeHash(provider);

                Assert.True(precomputedHashes.ContainsKey(provider), "The stored test hash dictionary has a comparison Hash, and same as HashableString");

                var precomputedTestHash = precomputedHashes[provider];
                var computedHashString = hf.ComputedHash.ToString();

                Assert.AreEqual(computedHashString, precomputedTestHash, "Computed and stored hash differ");
            }
        }

        /// <summary>
        /// Tests that HashableBytes HashableString HashableFile HashableStream all computer the same hash for the same ascii value
        /// Also tests that all types can be hased more than once
        /// </summary>
        [Test, Category("Hashing")]
        public void HashableFromsEquate() {

            var precomputedHashes = new Dictionary<HashProvider, string>() {
                { HashProvider.SHA256, @"AYSLdKSodmdJQlMzKiDoAZlUL09GgLyHr9VTZlhQtkg=" },
                { HashProvider.SHA384, @"TDQMTam7Wy20bTaD0vV7mCd760L4DNmsp55cgPnltRvVVf18qtTi/6ryuR4bXvJm" },
                { HashProvider.SHA512, @"NMp1zZdwa+MmPPwe6YoPe0eS1UxXk0sBCJN6tEzD0/BCHsqk9P282nwS3paL+XJRSdipcCb3EObB7F5r/qe6xQ==" }
            };

            var testFilePath = "HashableFromsEquate.txt";
            var testString = "60EC9927-35B3-4CCB-9791-56D0FF00F07B";
            File.WriteAllText(testFilePath, testString);
            
            var hBytes = new HashableBytes(Encoding.ASCII.GetBytes(testString));
            var hString = new HashableString(testString);
            var hFile = new HashableFile(testFilePath);
            var hStream = new HashableStream(new MemoryStream(Encoding.ASCII.GetBytes(testString)));

            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {

                hBytes.ComputeHash(provider);
                hString.ComputeHash(provider);
                hFile.ComputeHash(provider);
                hStream.ComputeHash(provider);

                Assert.True(precomputedHashes.ContainsKey(provider), "The stored test hash dictionary has a comparison Hash, and same as HashableString");

                var precomputedTestHash = precomputedHashes[provider];
                var hBytesString = hBytes.ComputedHash.ToString();

                Assert.AreEqual(hBytesString, precomputedTestHash, "Computed and stored hash differ");
                Assert.AreEqual(hBytesString, hString.ComputedHash.ToString());
                Assert.AreEqual(hBytesString, hFile.ComputedHash.ToString());
                Assert.AreEqual(hBytesString, hStream.ComputedHash.ToString());
            }
        }

        [Test, Category("Hashing")]
        public void HashableStringHashes() {

            var precomputedHashes = new Dictionary<HashProvider, string>() {
                { HashProvider.SHA256, @"QSz5LmQc4pbDAgZV0T7cfRW6vYHojRcdYIe/E/peFTY=" },
                { HashProvider.SHA384, @"mOMV/0r+ZC+qHvgrYnM7d5kGdsLjH5bNW75gEGwldFy5JEdJ2dctt9+aKBkX0lLV" },
                { HashProvider.SHA512, @"xl48gTfq6r+CxVxneqx9k3NGw0px6ubRdSnJUj/oR5MyabKlFC4FZwM2xBq0NkvM6lTOeQCGhZV0ET0EN11JZw==" }
            };

            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {
                var h = new HashableString("edb0f9cb-37a5-4c37-b8f7-7242e54bff34");
                var h2 = new HashableString("edb0f9cb-37a5-4c37-b8f7-7242e54bff3A");

                h.ComputeHash(provider);
                h2.ComputeHash(provider);

                Assert.True(precomputedHashes.ContainsKey(provider), "The stored test hash dictionary has a comparison Hash");

                var precomputedTestHash = precomputedHashes[provider];
                var computedHashString = h.ComputedHash.ToString();

                Assert.AreEqual(computedHashString, precomputedTestHash, "Computed and stored hash differ");
                Assert.AreNotEqual(h.ComputedHash, h2.ComputedHash, "Slightly different strings hash differently");
                Assert.AreNotEqual(h.Value, h2.Value, "Slightly different strings hash differently");

            }

        }

    }
}
