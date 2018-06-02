using System;
using CryptLink.SigningFramework;
using System.Security.Cryptography.X509Certificates;

namespace CryptLink.SigningFrameworkExamples
{
    class Program
    {
        static void Main(string[] args)
        {
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
