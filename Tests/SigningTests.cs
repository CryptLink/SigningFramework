using CryptLink;
using CryptLink.SigningFramework;
using NUnit.Framework;
using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;

namespace CryptLinkTests {

    [TestFixture]
    public class SignableTests {

        Cert signingCert1; //contains the public and private key
        Cert verifyCert1; //contains only the public key
        Cert signingCert2; //contains the public and private key
        Cert verifyCert2; //contains only the public key

        [SetUp]
        public void Setup_LoadCert() {
            signingCert1 = Cert.LoadFromPfx("Certs/ca1.pfx_testonly_donotuse", "");
            signingCert2 = Cert.LoadFromPfx("Certs/cert1.pfx_testonly_donotuse", "");

            verifyCert1 = signingCert1.RemovePrivateKey();
            verifyCert2 = signingCert2.RemovePrivateKey();

            Assert.True(signingCert1.HasPrivateKey);
            Assert.True(signingCert2.HasPrivateKey);
            Assert.False(verifyCert1.HasPrivateKey);
            Assert.False(verifyCert2.HasPrivateKey);
        }

        [Test]
        public void SigningTests() {
            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {
                var signed1 = new HashableString(Guid.NewGuid().ToString());
                signed1.ComputeHash(provider, signingCert1);

                var signed2 = new HashableString(signed1.Value);
                signed2.ComputeHash(provider, signingCert2);

                Assert.AreNotEqual(signingCert1.ComputedHash, signingCert2.ComputedHash, "Cert hashes do not match");
                Assert.AreEqual(signed1.ComputedHash, signed2.ComputedHash, "Signed hashes match");
                Assert.AreNotEqual(signed1.ComputedHash.SignatureCertHash, signed2.ComputedHash.SignatureCertHash, "Signed hashes match");
                Assert.AreNotEqual(signed1.ComputedHash.SignatureBytes, signed2.ComputedHash.SignatureBytes, "Signed hashes match");

                //The signed hashes verify as the should
                Assert.IsTrue(signed1.Verify(signingCert1));
                Assert.IsTrue(signed2.Verify(signingCert2));
                Assert.IsTrue(signed1.Verify(verifyCert1));
                Assert.IsTrue(signed2.Verify(verifyCert2));

                //but don't with the wrong certs
                Assert.IsFalse(signed2.Verify(signingCert1));
                Assert.IsFalse(signed1.Verify(signingCert2));
                Assert.IsFalse(signed2.Verify(verifyCert1));
                Assert.IsFalse(signed1.Verify(verifyCert2));

                //Change both hashes slightly
                if (signed1.ComputedHash.SignatureBytes[0] < Byte.MaxValue) {
                    signed1.ComputedHash.SignatureBytes[0]++;
                } else {
                    signed1.ComputedHash.SignatureBytes[0]--;
                }

                if (signed2.ComputedHash.SignatureBytes[0] < Byte.MaxValue) {
                    signed2.ComputedHash.SignatureBytes[0]++;
                } else {
                    signed2.ComputedHash.SignatureBytes[0]--;
                }

                //Neither should verify now
                Assert.IsFalse(signed1.Verify(signingCert1));
                Assert.IsFalse(signed2.Verify(signingCert2));
                Assert.IsFalse(signed1.Verify(verifyCert1));
                Assert.IsFalse(signed2.Verify(verifyCert2));
            }
        }

        [Test]
        public void HashVerifyTests() {
            foreach (HashProvider provider in Enum.GetValues(typeof(HashProvider))) {
                var signed = new HashableString(Guid.NewGuid().ToString());
                signed.ComputeHash(provider, signingCert1);

                Assert.IsTrue(signed.Verify());


                var unsigned = new HashableString(Guid.NewGuid().ToString());
                unsigned.ComputeHash(provider);



            }
        }


    }
}
