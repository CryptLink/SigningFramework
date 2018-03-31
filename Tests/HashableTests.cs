using CryptLink.SigningFramework;
using NUnit.Framework;
using System;
using System.Collections.Generic;

namespace CryptLinkTests {
    [TestFixture]
    public class HashableTests {

        [Test, Category("Hash")]
        public void HashableIsHashable() {
            Assert.False(this is IHashable, "This test should not derive from the Hashable type");
            Assert.False(new Hash() is IHashable, "A Hash should derive from the Hashable type");
            Assert.True(new HashableString("Test") is IHashable, "A HashableString should derive from the Hashable type");
        }

        [Test, Category("Hash")]
        public void HashableStringSerializeDeserialize() {

            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {
                var h1 = new HashableString("Test");
                h1.ComputeHash(provider);
                var h1s = Newtonsoft.Json.JsonConvert.SerializeObject(h1);
                var h1d = Newtonsoft.Json.JsonConvert.DeserializeObject<HashableString>(h1s);

                Assert.AreEqual(h1.ComputedHash, h1d.ComputedHash);
            }
        }

        [Test, Category("Hash")]
        public void HashableStringHashes() {

            var hashDictionary = new Dictionary<HashProvider, string>();
            //hashDictionary.Add(HashProvider.MD5, "DLxmEfVUC9CAmjiNyVphWw==");
            //hashDictionary.Add(HashProvider.SHA1, "ZAqyuuB77cTBY/Z5p0b3q3+10fo=");
            hashDictionary.Add(HashProvider.SHA256, "Uy6qvZV0iA2/drm4zACDLCCm7BE9aCKZVQ16bg80XiU=");
            hashDictionary.Add(HashProvider.SHA384, "e49GVAdrgOuWORHxnPrRqvQoXtSOgm9s3hsBp5qnP621RG5mf8T5BBd4LJEnBUDz");
            hashDictionary.Add(HashProvider.SHA512, "xu6eM89cZxWh0Uj9c/cxiIS0Gty5FgIeK8DoAKXF3Zf1FCF49q6IyP3Zjhr7DOTI0sVLXzezC32hmXuzOwuKMQ==");

            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {
                var h = new HashableString("Test");
                h.ComputeHash(provider);

                Assert.True(hashDictionary.ContainsKey(provider), "The stored test hash dictionary has a comparison Hash");

                var storedTestHash = hashDictionary[provider];
                var computedHashString = h.ComputedHash.ToString();

                Assert.AreEqual(computedHashString, storedTestHash, "Computed and stored hash differ, the hash of 'Test' should never change");
            }
            
        }

    }
}
