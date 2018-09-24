using NUnit.Framework;
using System;
using System.Linq;
using System.Collections.Generic;
using CryptLink.SigningFramework;

namespace CryptLinkTests {
	[TestFixture()]
	public class HashTests {

        [Test(), Category("Hashing")]
        public void HashCreateOverloads() {
            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {

                var h1 = Hash.Compute(Guid.NewGuid().ToString(), provider);
                var h1FromBytes = Hash.FromComputedBytes(h1.Bytes, provider, h1.SourceByteLength, h1.ComputedDate);
                var h1FromB64 = Hash.FromB64(Utility.EncodeBytes(h1.Bytes), provider, h1.SourceByteLength, h1.ComputedDate);

                Assert.AreEqual(h1.Bytes, h1FromBytes.Bytes, "Compared Bitwise");
                Assert.True(h1 == h1FromBytes, "Compared with equality");
                Assert.True(h1.ComputedDate == h1FromBytes.ComputedDate, "Date is correct");
                Assert.True(h1.Provider == h1FromBytes.Provider, "Provider is correct");

                Assert.AreEqual(h1.Bytes, h1FromB64.Bytes, "Compared Bitwise");
                Assert.True(h1 == h1FromB64, "Compared with equality");
                Assert.True(h1.ComputedDate == h1FromB64.ComputedDate, "Date is correct");
                Assert.True(h1.Provider == h1FromB64.Provider, "Provider is correct");
            }
        }

        [Test(), Category("Hashing")]
        public void HashSerializeDeseralize() {
            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {
                var h1 = Hash.Compute(Guid.NewGuid().ToString(), provider);

                var h1Serialized = Newtonsoft.Json.JsonConvert.SerializeObject(h1);
                var h1Deserialized = Newtonsoft.Json.JsonConvert.DeserializeObject<Hash>(h1Serialized);

                Assert.AreEqual(h1.Bytes, h1Deserialized.Bytes, "Compared Bitwise");
                Assert.True(h1 == h1Deserialized, "Compared with equality");
            }
        }

        [Test(), Category("Hashing")]
        public void HashCreateLength() {
            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {
                var h1 = Hash.Compute(Guid.NewGuid().ToString(), provider);
                
                var tooLong = h1.Bytes.Concat(BitConverter.GetBytes(true)).ToArray();
                Assert.Throws<ArgumentException>(delegate {
                    var h1TooLong = Hash.FromComputedBytes(tooLong, provider, h1.SourceByteLength, DateTimeOffset.Now);
                });

                var tooShort = h1.Bytes.Take(h1.Bytes.Length - 1).ToArray();
                Assert.Throws<ArgumentException>(delegate {
                    var h1TooShort = Hash.FromComputedBytes(tooShort, provider, h1.SourceByteLength, DateTimeOffset.Now);
                });

            }
        }


        [Test(), Category("Hash Compare")]
        public void HashCompareString() {

            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {
                var tempGuid = Guid.NewGuid().ToString();
                var hash1 = Hash.Compute(tempGuid, provider);
                var hash2 = Hash.Compute(tempGuid, provider);
                var hash3 = Hash.Compute(tempGuid.ToUpper(), provider);
                var hash4 = Hash.Compute("", provider);

                Assert.AreEqual(hash1.Provider, provider,
                    "HashProvider is set correctly");

                Assert.AreEqual(hash1.Bytes, hash2.Bytes,
                    "'TEST' and 'TEST' hashes are equal for provider: '" + provider.ToString() + "'");
                Assert.AreNotEqual(hash2.Bytes, hash3.Bytes,
                    "'TEST' and 'test' hashes are NOT equal for provider: '" + provider.ToString() + "'");

                Assert.True(hash1.CompareTo(hash2) == 0,
                    "Separate hashes of the same string compare returns true for provider: '" + provider.ToString() + "'");

                Assert.False(hash1.CompareTo(hash3) == 0,
                    "Separate hashes of the different case strings returns false for provider: '" + provider.ToString() + "'");


            }
        }

        [Test(), Category("Hash Compare")]
        public void HashToHashOperators() {
            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {
                var tempGuid = Guid.NewGuid().ToString();
                var h1 = Hash.Compute(tempGuid, provider);
                var h2 = Hash.Compute(tempGuid, provider);
                var h3 = Hash.Compute(tempGuid.ToUpper(), provider);

                byte[] maxBytes = new byte[h1.HashByteLength()];
                byte[] minBytes = new byte[h1.HashByteLength()];

                for (var i = 0; i < maxBytes.Length; i++) {
                    maxBytes[i] = 255;
                    minBytes[i] = 0;
                }

                Hash max = Hash.FromComputedBytes(maxBytes, provider, null, null);
                Hash min = Hash.FromComputedBytes(minBytes, provider, null, null);

                //All operators (hash to binary)
                Assert.True(h1 == h2,
                    "Operator '==' compares correctly for provider (Hash to Hash): '" + provider.ToString() + "'");
                Assert.False(h1 == h3,
                    "Operator '==' compares correctly for provider (Hash to Hash): '" + provider.ToString() + "'");

                Assert.False(h1 != h2,
                    "Operator '!=' compares correctly for provider (Hash to Hash): '" + provider.ToString() + "'");
                Assert.True(h1 != h3,
                    "Operator '!=' compares correctly for provider (Hash to Hash): '" + provider.ToString() + "'");

                Assert.True(h1 > min,
                    "Operator '>' compares correctly for provider (Hash to Hash): '" + provider.ToString() + "'");
                Assert.True(h3 > min,
                    "Operator '>' compares correctly for provider (Hash to Hash): '" + provider.ToString() + "'");

                Assert.True(h1 < max,
                    "Operator '<' compares correctly for provider (Hash to Hash): '" + provider.ToString() + "'");
                Assert.True(h3 < max,
                    "Operator '<' compares correctly for provider (Hash to Hash): '" + provider.ToString() + "'");

                Assert.True(h1 >= min,
                    "Operator '>=' compares correctly for provider (Hash to Hash): '" + provider.ToString() + "'");
                Assert.True(h3 >= min,
                    "Operator '>=' compares correctly for provider (Hash to Hash): '" + provider.ToString() + "'");

                Assert.True(h1 <= max,
                    "Operator '<=' compares correctly for provider (Hash to Hash): '" + provider.ToString() + "'");
                Assert.True(h3 <= max,
                    "Operator '<=' compares correctly for provider (Hash to Hash): '" + provider.ToString() + "'");
            }
        }

        [Test(), Category("Hash Compare")]
        public void HashToBinaryOperators() {
            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {
                var tempGuid = Guid.NewGuid().ToString();
                var h1 = Hash.Compute(tempGuid, provider);
                var h2 = Hash.Compute(tempGuid, provider);
                var h3 = Hash.Compute(tempGuid.ToUpper(), provider);

                byte[] max = new byte[h1.HashByteLength()];
                byte[] min = new byte[h1.HashByteLength()];

                for (var i = 0; i < max.Length; i++) {
                    max[i] = 255;
                    min[i] = 0;
                }

                //All operators (hash to binary)
                Assert.True(h1 == h2.Bytes,
                    "Operator '==' compares correctly for provider (Hash to binary): '" + provider.ToString() + "'");
                Assert.False(h1 == h3.Bytes,
                    "Operator '==' compares correctly for provider (Hash to binary): '" + provider.ToString() + "'");

                Assert.False(h1 != h2.Bytes,
                    "Operator '!=' compares correctly for provider (Hash to binary): '" + provider.ToString() + "'");
                Assert.True(h1 != h3.Bytes,
                    "Operator '!=' compares correctly for provider (Hash to binary): '" + provider.ToString() + "'");

                Assert.True(h1 > min,
                    "Operator '>' compares correctly for provider (Hash to binary): '" + provider.ToString() + "'");
                Assert.True(h3 > min,
                    "Operator '>' compares correctly for provider (Hash to binary): '" + provider.ToString() + "'");

                Assert.True(h1 < max,
                    "Operator '<' compares correctly for provider (Hash to binary): '" + provider.ToString() + "'");
                Assert.True(h3 < max,
                    "Operator '<' compares correctly for provider (Hash to binary): '" + provider.ToString() + "'");

                Assert.True(h1 >= min,
                    "Operator '>=' compares correctly for provider (Hash to binary): '" + provider.ToString() + "'");
                Assert.True(h3 >= min,
                    "Operator '>=' compares correctly for provider (Hash to binary): '" + provider.ToString() + "'");

                Assert.True(h1 <= max,
                    "Operator '<=' compares correctly for provider (Hash to binary): '" + provider.ToString() + "'");
                Assert.True(h3 <= max,
                    "Operator '<=' compares correctly for provider (Hash to binary): '" + provider.ToString() + "'");
            }
        }

        [Test(), Category("Hash Compare")]
        public void BinaryToHashOperators() {
            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {
                var tempGuid = Guid.NewGuid().ToString();
                var h1 = Hash.Compute(tempGuid, provider);
                var h2 = Hash.Compute(tempGuid, provider);
                var h3 = Hash.Compute(tempGuid.ToUpper(), provider);

                byte[] maxBytes = new byte[h1.HashByteLength()];
                byte[] minBytes = new byte[h1.HashByteLength()];

                for (var i = 0; i < maxBytes.Length; i++) {
                    maxBytes[i] = 255;
                    minBytes[i] = 0;
                }

                Hash max = Hash.FromComputedBytes(maxBytes, provider, null, null);
                Hash min = Hash.FromComputedBytes(minBytes, provider, null, null);

                //All operators (hash to binary)
                Assert.True(h1.Bytes == h2,
                    "Operator '==' compares correctly for provider (binary to Hash): '" + provider.ToString() + "'");
                Assert.False(h1.Bytes == h3,
                    "Operator '==' compares correctly for provider (binary to Hash): '" + provider.ToString() + "'");

                Assert.False(h1.Bytes != h2,
                    "Operator '!=' compares correctly for provider (binary to Hash): '" + provider.ToString() + "'");
                Assert.True(h1.Bytes != h3,
                    "Operator '!=' compares correctly for provider (binary to Hash): '" + provider.ToString() + "'");

                Assert.True(h1.Bytes > min,
                    "Operator '>' compares correctly for provider (binary to Hash): '" + provider.ToString() + "'");
                Assert.True(h3.Bytes > min,
                    "Operator '>' compares correctly for provider (binary to Hash): '" + provider.ToString() + "'");

                Assert.True(h1.Bytes < max,
                    "Operator '<' compares correctly for provider (binary to Hash): '" + provider.ToString() + "'");
                Assert.True(h3.Bytes < max,
                    "Operator '<' compares correctly for provider (binary to Hash): '" + provider.ToString() + "'");

                Assert.True(h1.Bytes >= min,
                    "Operator '>=' compares correctly for provider (binary to Hash): '" + provider.ToString() + "'");
                Assert.True(h3.Bytes >= min,
                    "Operator '>=' compares correctly for provider (binary to Hash): '" + provider.ToString() + "'");

                Assert.True(h1.Bytes <= max,
                    "Operator '<=' compares correctly for provider (binary to Hash): '" + provider.ToString() + "'");
                Assert.True(h3.Bytes <= max,
                    "Operator '<=' compares correctly for provider (binary to Hash): '" + provider.ToString() + "'");
            }
        }

        [Test(), Category("Hash Compare")]
        public void HashSorting() {
            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {
                
                var h1 = Hash.Compute(Guid.NewGuid().ToString(), provider);
                var h2 = Hash.Compute(Guid.NewGuid().ToString(), provider);
                var h3 = Hash.Compute(Guid.NewGuid().ToString(), provider);

                var hList = new List<Hash>();
                hList.Add(h1);
                hList.Add(h2);
                hList.Add(h3);

                Assert.IsNotEmpty(hList);
                Assert.AreEqual(hList.Count, 3);

                hList.Sort();

            }
        }

        [Test(), Category("Hash Compare")]
        public void HashCompareToNull() {
            //Checking nulls with custom comparer can be tricky, here are all the ways I am aware of checking it

            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {
                Hash hash1 = Hash.Compute(Guid.NewGuid().ToString(), provider);
                Hash hash2 = null;

                Assert.NotNull(hash1, "New hash is not null");
                Assert.True(hash2 == null, "New hash is not null using ==");
                Assert.False(ReferenceEquals(hash1, null), "New hash is not null using ReferenceEquals()");
                Assert.True(hash1 != (Hash)null, "New hash is not null");
                Assert.True(hash1 != default(Hash), "New hash is not null");
                Assert.True(hash1?.Bytes != null, "New hash is not null");

                Assert.Null(hash2, "Null hash is null");
                Assert.True(hash2 == null, "Null hash is null using ==");
                Assert.True(ReferenceEquals(hash2, null), "Null hash is null using ReferenceEquals()");
				Assert.True(hash2 == (Hash)null, "Null hash is null using (Hash)null");
				Assert.True(hash2 == default(Hash), "Null hash is null using default(Hash)");
                Assert.True(hash2?.Bytes == null, "Null hash is null using Hash?.Bytes");
            }
        }


        [Test(), Category("Hashing")]
        public void HashProviderToOID() {
            var providerOIDs = new Dictionary<HashProvider, string>();
            //providerOIDs.Add(HashProvider.MD5, "1.2.840.113549.2.5");
            //providerOIDs.Add(HashProvider.SHA1, "1.3.14.3.2.26");
            providerOIDs.Add(HashProvider.SHA256, "2.16.840.1.101.3.4.2.1");
            providerOIDs.Add(HashProvider.SHA384, "2.16.840.1.101.3.4.2.2");
            providerOIDs.Add(HashProvider.SHA512, "2.16.840.1.101.3.4.2.3");

            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {
                Assert.True(providerOIDs.ContainsKey(provider), "Test dictionary contains providers.");

                var providerOIDLookup = providerOIDs[provider];
                var providerOID = provider.GetOID().Value;

                Assert.AreEqual(providerOIDLookup, providerOID);
            }
        }


    }

}

