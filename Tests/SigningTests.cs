using CryptLink.HashFramework;
using NUnit.Framework;
using System;

namespace CryptLinkTests {

    [TestFixture]
    public class SignableTests {

        Cert signingCert1; //contains the public and private key
        Cert verifyCert1; //contains only the public key
        Cert signingCert2; //contains the public and private key
        Cert verifyCert2; //contains only the public key

        [TestFixtureSetUp]
        public void Setup_GenerateCert() {
            //signingCert1 = new CertBuilder { SubjectName = "CN=Test CA1", KeyStrength = 1024 }.BuildCert();
            //signingCert2 = new CertBuilder { SubjectName = "CN=Test CA2", KeyStrength = 1024 }.BuildCert();

            verifyCert1 = signingCert1.RemovePrivateKey();
            verifyCert2 = signingCert2.RemovePrivateKey();

            Assert.True(signingCert1.HasPrivateKey);
            Assert.True(signingCert2.HasPrivateKey);
            Assert.False(verifyCert1.HasPrivateKey);
            Assert.False(verifyCert2.HasPrivateKey);

        }

        [Test]
        public void SigningTests() {
            foreach (Hash.HashProvider provider in Enum.GetValues(typeof(Hash.HashProvider))) {
                var signed1 = new HashableString("Test", provider, signingCert1);
                var signed2 = new HashableString("Test", provider, signingCert2);

                Assert.AreNotEqual(signingCert1.ComputedHash, signingCert2.ComputedHash, "Cert hashes do not match");
                Assert.AreEqual(signed1.ComputedHash, signed2.ComputedHash, "Signed hashes match");
                Assert.AreNotEqual(signed1.ComputedHash.SignatureCertHash, signed2.ComputedHash.SignatureCertHash, "Signed hashes match");
                Assert.AreNotEqual(signed1.ComputedHash.SignatureBytes, signed2.ComputedHash.SignatureBytes, "Signed hashes match");

                Assert.IsTrue(signed1.Verify(signingCert1));
                Assert.IsTrue(signed2.Verify(signingCert2));
                Assert.IsTrue(signed1.Verify(verifyCert1));
                Assert.IsTrue(signed2.Verify(verifyCert2));

                Assert.IsFalse(signed2.Verify(signingCert1));
                Assert.IsFalse(signed1.Verify(signingCert2));
                Assert.IsFalse(signed2.Verify(verifyCert1));
                Assert.IsFalse(signed1.Verify(verifyCert2));
            }
        }

        [Test]
        public void SignedVerifyTests() {

        }

    }
}
