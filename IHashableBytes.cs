namespace CryptLink.SigningFramework {

    /// <summary>
    /// Interface to be implemented by any object that supports hashing by the framework
    /// </summary>
    public interface IHashableBytes : IHashable {

        /// <summary>
        /// A byte array of data to be hashed
        /// </summary>
        byte[] GetHashableData();

    }
}
