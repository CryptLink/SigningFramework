using System;
using CryptLink.SigningFramework;
using System.Linq;
using System.Text;
using System.Collections.Generic;

namespace CryptLink.SigningFrameworkExamples
{
    /// <summary>
    /// A simple example of a hasable object
    /// </summary>
    [Serializable]
    public class HashableWidgetExample : Hashable {

        [HashProperty]
        public int ID { get; set; }
        [HashProperty]
        public string Name { get; set; }
        [HashProperty]
        public float Price { get; set; }

        /// <summary>
        /// A field that does not change the hash
        /// </summary>
        public int PurchaseCount { get; set; }

        public override byte[] GetHashableData() {
            //This implementation uses Binary Seralization to get the data to hash, but you can implement a custom method if you prefer
            //https://docs.microsoft.com/en-us/dotnet/standard/serialization/serialization-guidelines


        }
    }
}
