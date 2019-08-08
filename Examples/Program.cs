using System;
using CryptLink.SigningFramework;
using System.Security.Cryptography.X509Certificates;
using System.IO;

namespace CryptLink.SigningFrameworkExamples
{
    class Program
    {
        static void Main(string[] args)
        {

            // Make some values to hash
            string stringToHash = "Easy!";
            byte[] bytesToHash = new byte[] { 0x45, 0x61, 0x73, 0x79, 0x21 };
            Stream streamToHash = new MemoryStream(new byte[] { 0x45, 0x61, 0x73, 0x79, 0x21 });
            File.WriteAllText("CryptLinkDemo.txt", "Easy!");
            Stream fileToHash = new FileStream("CryptLinkDemo.txt", FileMode.Open);

            // Using Extentions
            stringToHash.ComputeHash(HashProvider.SHA256);
            bytesToHash.ComputeHash(HashProvider.SHA256);
            streamToHash.ComputeHash(HashProvider.SHA256);
            fileToHash.ComputeHash(HashProvider.SHA256);

            // Using Hash static methods
            Hash.Compute(stringToHash, HashProvider.SHA256);
            Hash.Compute(bytesToHash, HashProvider.SHA256);
            Hash.Compute(streamToHash, HashProvider.SHA256);
            Hash.Compute(fileToHash, HashProvider.SHA256);


            // Instanced examples, the value and hash are combined into a meta object
            // HashableString, holds the original string and the hash
            var hashableString = new HashableString("Easy!", HashProvider.SHA256);

            // HashableBytes, holds the original set of bytes and the hash - best for small arrays of bytes
            var hashableBytes = new HashableBytes(new byte[] { 0x45, 0x61, 0x73, 0x79, 0x21 }, HashProvider.SHA256);

            // HashableFile, holds a refernce to a local file path and the hash
            var hashableFile = new HashableFile("CryptLinkDemo.txt", HashProvider.SHA256);

            var widget = new HashableWidgetExample() {
                ID = 0,
                Name = "Widget",
                Price = 100,
                PurchaseCount = 1000000
            };

            widget.ComputeHash(HashProvider.SHA256);
            Console.WriteLine(widget.ComputedHash);


            using (X509Store store = new X509Store(StoreName.My, StoreLocation.LocalMachine)) {
                store.Open(OpenFlags.ReadOnly);
                X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindBySerialNumber, "123456", true);
                var cert = new Cert(certs[0]);

                widget.ComputeHash(HashProvider.SHA256, cert);
                widget.Verify(cert);
            }
            
        }
    }
}
