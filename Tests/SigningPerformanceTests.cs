using NUnit.Framework;
using System;
using System.Collections.Generic;
using CryptLink.SigningFramework;


namespace CryptLink.SigningFrameworkTests {
    [TestFixture]
    public class SigningPerformanceTests {
        private TimeSpan TestLength = new TimeSpan(0, 0, 0, 2, 500);
        private long TestByteLength = 1024 * 128;
        private Random random = new Random();

        [Test, Category("Performance"), Category("Optional")]
        public void HashingPerformance() {
            var results = GetTestSizeString();
            var hItem = new HashableBytes(GetBytes());

            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider)) ) {

                long hashCount = 0;
                DateTime startTime = DateTime.Now;

                while ((startTime + TestLength) > DateTime.Now) {
                    hItem.ComputeHash(provider);
                    hashCount++;
                }

                results += GetResultString(provider, hashCount);
            }

            Assert.Pass(results);
        }

        [Test, Category("Performance"), Category("Optional")]
        public void HashVerifyPerformance() {
            var results = GetTestSizeString();
            var hItem = new HashableBytes(GetBytes());

            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {

                long hashCount = 0;
                DateTime startTime = DateTime.Now;
                hItem.ComputeHash(provider);

                while ((startTime + TestLength) > DateTime.Now) {
                    hItem.Verify();
                    hashCount++;
                }

                results += GetResultString(provider, hashCount);
            }

            Assert.Pass(results);
        }

        [Test, Category("Performance"), Category("Optional")]
        public void SigningPerformance() {
            var results = GetTestSizeString();
            var hItem = new HashableBytes(GetBytes());

            var signingCert = Cert.LoadFromPfx("Certs/ca1.pfx_testonly_donotuse", "");

            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {

                long hashCount = 0;
                DateTime startTime = DateTime.Now;

                while ((startTime + TestLength) > DateTime.Now) {
                    hItem.ComputeHash(provider, signingCert);
                    hashCount++;
                }

                results += GetResultString(provider, hashCount);
            }

            Assert.Pass(results);
        }

        [Test, Category("Performance"), Category("Optional")]
        public void SignedVerifyPerformance() {
            var results = GetTestSizeString();
            var hItem = new HashableBytes(GetBytes());

            var signingCert = Cert.LoadFromPfx("Certs/ca1.pfx_testonly_donotuse", "");

            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {

                long hashCount = 0;
                DateTime startTime = DateTime.Now;
                hItem.ComputeHash(provider, signingCert);

                while ((startTime + TestLength) > DateTime.Now) {
                    hItem.Verify(signingCert);
                    hashCount++;
                }

                results += GetResultString(provider, hashCount);
            }

            Assert.Pass(results);
        }

        private byte[] GetBytes() {
            var b = new byte[TestByteLength];
            random.NextBytes(b);
            return b;
        }

        private string GetTestSizeString() {
            return $"Test size: {(TestByteLength / 1024).ToString("n0")}k, length: {TestLength}\r\n";
        }

        private string GetResultString(HashProvider Provider, long HashCount) {
            return $"{Provider}: hashed {HashCount.ToString("n0")} times, ({(HashCount / TestLength.TotalSeconds).ToString("n0")} per sec)\r\n";
        }

    }

}
