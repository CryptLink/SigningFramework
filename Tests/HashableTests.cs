using CryptLink.SigningFramework;
using NUnit.Framework;
using System;
using System.Collections.Generic;

namespace CryptLinkTests {
    [TestFixture]
    public class HashableTests {

        [Test, Category("Hashing")]
        public void HashableIsHashable() {
            Assert.False(this is IHashable, "This test should not derive from the Hashable type");
            Assert.False(new Hash() is IHashable, "A Hash should derive from the Hashable type");
            Assert.True(new HashableString(Guid.NewGuid().ToString()) is IHashable, "A HashableString should derive from the Hashable type");
        }

        [Test, Category("Hashing"), Category("Serialization")]
        public void HashableStringSerializeDeserialize() {

            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {
                var h1 = new HashableString(Guid.NewGuid().ToString());
                h1.ComputeHash(provider);
                var h1s = Newtonsoft.Json.JsonConvert.SerializeObject(h1);
                var h1d = Newtonsoft.Json.JsonConvert.DeserializeObject<HashableString>(h1s);

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

                Assert.AreEqual(h1.ComputedHash, h1d.ComputedHash);
                Assert.AreEqual(h1.Value, h1d.Value);
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

                Assert.AreEqual(computedHashString, precomputedTestHash, "Computed and stored hash differ, the hash of 'Test' should never change");
                Assert.AreNotEqual(h.ComputedHash, h2.ComputedHash, "Slightly different strings hash differently");
                Assert.AreNotEqual(h.Value, h2.Value, "Slightly different strings hash differently");

            }

        }

    }
}
