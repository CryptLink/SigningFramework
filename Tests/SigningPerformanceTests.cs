using NUnit.Framework;
using System;
using System.Collections.Generic;
using CryptLink.SigningFramework;


namespace CryptLink.SigningFrameworkTests {
    [TestFixture]
    public class SigningPerformanceTests {
        private TimeSpan TestLength = new TimeSpan(0, 0, 5);
        private long TestByteLength = 1024 * 128;

        [Test, Category("Performance"), Category("Optional")]
        public void HashingPerformance() {
            var results = $"Test size: {(TestByteLength/1024).ToString("n0")}k, length: {TestLength}\r\n";
            var r = new Random();

            var hItem = new HashableBytes();
            hItem.Value = new byte[TestByteLength];
            r.NextBytes(hItem.Value);
            
            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider)) ) {

                long hashCount = 0;
                DateTime startTime = DateTime.Now;

                while ((startTime + TestLength) > DateTime.Now) {
                    hItem.ComputeHash(provider);
                    hashCount++;
                }

                results += $"{provider}: hashed {hashCount.ToString("n0")} times, ({(hashCount / TestLength.TotalSeconds).ToString("n0")} per sec)\r\n";
            }

            Assert.Pass(results);
        }

        [Test, Category("Performance"), Category("Optional")]
        public void SigningPerformance() {
            var results = $"Test size: {(TestByteLength / 1024).ToString("n0")}k, length: {TestLength}\r\n";
            var r = new Random();

            var hItem = new HashableBytes();
            hItem.Value = new byte[TestByteLength];
            r.NextBytes(hItem.Value);

            var signingCert = Cert.LoadFromPfx("Certs/ca1.pfx_testonly_donotuse", "");

            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {

                long hashCount = 0;
                DateTime startTime = DateTime.Now;

                while ((startTime + TestLength) > DateTime.Now) {
                    hItem.ComputeHash(provider, signingCert);
                    hashCount++;
                }

                results += $"{provider}: hashed {hashCount.ToString("n0")} times, ({(hashCount / TestLength.TotalSeconds).ToString("n0")} per sec)\r\n";
            }

            Assert.Pass(results);
        }

    }


    public class HashableBytes : Hashable {
        public byte[] Value { get; set; }

        public override byte[] GetHashableData() {
            return Value;
        }
    }

}
