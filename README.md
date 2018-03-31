# CryptLink.SigningFramework
A generic framework for hashing and signing arbitrary objects using interfaces. Also implements x509Certificate management features.

## Examples
The signing framework strives to make common cryptography related tasks simple and extensible. We believe good security should be as simple as as their concepts, and extensible to any object.

### Hashing
``` C#
var hashedString = new HashableString(args[0]);
hashedString.ComputeHash(HashProvider.SHA256);
Console.WriteLine($"{hashedString.Value}: {hashedString.ComputedHash}");
```

### Signing

### Extending



## Features
This library implements a number of convenient classes, abstractions and interfaces, below are the major classes in order of abstraction.

### IComparable
The standard class for implementing any comparable (and sortable) object, provided by dotnet standard.

### CompareableBytesAbstract
CryptLink's lowest level abstract implementation of a comparable array of bytes. Not intended to be used directly, but implements functions for all IComparison interfaces.

### CompareableBytes
A minimal class for implementing ComparableBytesAbstract. Lowest level type intended for storing bytes that need to be compared or sorted.

### Hash
Implements ComparableBytes and adds features for computing the hash for arbitrary bytes.

### IHashable
Interface that requires the basic properties and functions needed to hash a object.

### Hashable
Abstract that implements basic functionality for computing and verifying hashes of any IHashable object. 

### HashableString
A sample implementation of Hashable that makes strings hashable and signable. 
If you would like to make any object hashable, this is a simple example.

### Cert
A wrapper for X509Certificate2 that implements Hashable and several storage and protection methods