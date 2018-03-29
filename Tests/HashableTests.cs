using CryptLink.SigningFramework;
using NUnit.Framework;
using System;
using System.Collections.Generic;

namespace CryptLinkTests {
    [TestFixture]
    public class HashableTests {

        [Test, Category("Hash")]
        public void HashableIsHashable() {
            Assert.False(this is IHashable, "A HashableTest should not derive from the Hashable type");
            Assert.False(new Hash() is IHashable, "A Hash should not derive from the Hashable type");
            Assert.True(new HashableString("Test", Hash.HashProvider.MD5) is IHashable, "A HashableString should derive from the Hashable type");
        }

        [Test, Category("Hash")]
        public void HashableStringSerializeDeserialize() {
            var h1 = new HashableString("Test", Hash.HashProvider.SHA256);
            var h1s = Newtonsoft.Json.JsonConvert.SerializeObject(h1);
            var h1d = Newtonsoft.Json.JsonConvert.DeserializeObject<HashableString>(h1s);

            Assert.AreEqual(h1.ComputedHash, h1d.ComputedHash);
        }

        [Test, Category("Hash")]
        public void HashableStringHashes() {

            var hashDictionary = new Dictionary<Hash.HashProvider, string>();
            hashDictionary.Add(Hash.HashProvider.MD5, "DLxmEfVUC9CAmjiNyVphWw==");
            hashDictionary.Add(Hash.HashProvider.SHA1, "ZAqyuuB77cTBY/Z5p0b3q3+10fo=");
            hashDictionary.Add(Hash.HashProvider.SHA256, "Uy6qvZV0iA2/drm4zACDLCCm7BE9aCKZVQ16bg80XiU=");
            hashDictionary.Add(Hash.HashProvider.SHA384, "e49GVAdrgOuWORHxnPrRqvQoXtSOgm9s3hsBp5qnP621RG5mf8T5BBd4LJEnBUDz");
            hashDictionary.Add(Hash.HashProvider.SHA512, "xu6eM89cZxWh0Uj9c/cxiIS0Gty5FgIeK8DoAKXF3Zf1FCF49q6IyP3Zjhr7DOTI0sVLXzezC32hmXuzOwuKMQ==");

            foreach (Hash.HashProvider provider in Enum.GetValues(typeof(Hash.HashProvider))) {
                var h = new HashableString("Test", provider);

                Assert.True(hashDictionary.ContainsKey(provider), "The stored test hash dictionary has a comparison Hash");

                var storedTestHash = hashDictionary[provider];
                var computedHashString = h.ComputedHash.ToString();

                Assert.AreEqual(computedHashString, storedTestHash, "Computed and stored hash differ, the hash of 'Test' should never change");
            }
            
        }

    }
}
