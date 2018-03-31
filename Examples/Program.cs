using System;
using CryptLink.SigningFramework;

namespace CryptLink.SigningFrameworkExamples
{
    class Program
    {
        static void Main(string[] args)
        {
            var hashedString = new HashableString("Test");
            hashedString.ComputeHash(HashProvider.SHA256);
            Console.WriteLine($"{hashedString.Value}: {hashedString.ComputedHash}");
        }
    }
}
