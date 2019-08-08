using System.IO;

namespace CryptLink.SigningFramework {

    /// <summary>
    /// Interface to be implemented by any streamable object that supports hashing by the framework
    /// </summary>
    public interface IHashableStream : IHashable {

        /// <summary>
        /// The stream to be hashed
        /// </summary>
        Stream GetHashableStream();

    }
}
