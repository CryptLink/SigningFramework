using System;
using System.Collections.Generic;
using System.Text;

namespace CryptLink.SigningFramework
{
    /// <summary>
    /// A simple attribute for marking which fields in a class contribute to a hash
    /// </summary>
    [AttributeUsage(AttributeTargets.Property, AllowMultiple = false)]
    public class HashProperty : Attribute {
    }
}
