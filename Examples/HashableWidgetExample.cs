using System;
using CryptLink.SigningFramework;
using System.Linq;
using System.Text;
using System.Collections.Generic;

namespace CryptLink.SigningFrameworkExamples
{
    public class HashableWidgetExample : Hashable {
        public int ID { get; set; }
        public string Name { get; set; }
        public float Price { get; set; }

        public override byte[] GetHashableData() {
            return (IEnumerable)(BitConverter.GetBytes(ID)).Append(BitConverter.GetBytes(Price));
                //.Append(Encoding.ASCII.GetBytes(Name))
                //.Append(BitConverter.GetBytes(Price));
        }
    }
}
