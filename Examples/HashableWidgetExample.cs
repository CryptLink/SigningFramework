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
            return GetHashablePropertyData();
        }
    }
}
