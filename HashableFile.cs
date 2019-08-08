using System;
using System.IO;
using System.Text;

namespace CryptLink.SigningFramework {

    /// <summary>
    /// A immutable byte[] that can easily be hashed
    /// </summary>
    public class HashableFile : IHashableStream {

        private string _filePath = null;
        public Hash ComputedHash { get; set; }

        public FileInfo GetFileInfo() {
            return new FileInfo(_filePath);
        }

        public string FilePath {
            get { return _filePath; }
            set {
                if (_filePath != value) {
                    ComputedHash = null;
                    _filePath = value;
                }
            }
        }

        public HashableFile() { }

        public HashableFile(string FilePath) {
            _filePath = FilePath;
        }

        /// <summary>
        /// Creates a hashable file, computes the hash immediately
        /// </summary>
        public HashableFile(string FilePath, HashProvider Provider) {
            _filePath = FilePath;
            this.ComputeHash(Provider);
        }

        /// <summary>
        /// Creates a hashable file, computes the hash and signature immediately
        /// </summary>
        public HashableFile(string FilePath, HashProvider Provider, Cert SigningCert) {
            _filePath = FilePath;
            this.ComputeHash(Provider, SigningCert);
        }

        /// <summary>
        /// Saves a stream to a file returns a new HashableFile
        /// </summary>
        /// <param name="StreamToSave">A stream to save to a file</param>
        /// <param name="Provider">If specified computes the hash after writing the file</param>
        /// <param name="SigningCert">If specified with a valid Provider, computes the signature after writing the file</param>
        public HashableFile(Stream StreamToSave, HashProvider? Provider = null, Cert SigningCert = null) {
            _filePath = FilePath;

            using (var fileStream = File.Create(_filePath)) {
                StreamToSave.Seek(0, SeekOrigin.Begin);
                StreamToSave.CopyTo(fileStream);
            }

            if (Provider.HasValue) {
                this.ComputeHash(Provider.Value, SigningCert);
            }
        }
    

        public Stream GetHashableStream() {
            if (!File.Exists(_filePath)) {
                throw new FileNotFoundException($"File does not exist: {_filePath}");
            }

            return new FileStream(_filePath, FileMode.Open, FileAccess.Read);
        }


        public bool Verify() {
            string n = null;
            return ComputedHash.Verify(GetHashableStream(), out n);
        }

        public bool Verify(out string Reason) {
            return ComputedHash.Verify(GetHashableStream(), out Reason);
        }

        public bool Verify(Cert SigningPublicCert) {
            string n = null;
            return ComputedHash.Verify(GetHashableStream(), out n, SigningPublicCert);
        }

        /// <summary>
        /// Verifies the hash and signature of an object
        /// </summary>
        /// <param name="SigningPublicCert"></param>
        /// <returns>Returns TRUE if the hash and signature verify correctly</returns>
        public bool Verify(Cert SigningPublicCert, out string Reason) {
            return ComputedHash.Verify(GetHashableStream(), out Reason, SigningPublicCert);
        }


        public void ComputeHash(HashProvider Provider, Cert SigningCert) {
            ComputedHash = Hash.Compute(GetHashableStream(), Provider, SigningCert);
        }

        public void ComputeHash(HashProvider Provider) {
            ComputeHash(Provider, null);
        }

        Stream _value;
        public Stream Value {
            get { return _value; }
            set {
                if (value != _value) {
                    this.ComputedHash = null;
                    _value = value;
                }
            }
        }


    }
}
