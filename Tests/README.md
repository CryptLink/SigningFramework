# CryptLink.SigningFrameworkTests

Here lies the tests of SigningFramework, arbiter of good and bad code.

## About
Tests use the Nunit framework, with a little help from dotnet. 

### Command Line (All OSes)

* Ensure that `dotnet` is installed, if not see: (https://www.microsoft.com/net/download)
* Open a terminal and navigate to your local clone of SigningFramework
* Restore all nuget packages using `dotnet restore`
* Navigate to the `Tests` folder
* Run tests with `dotnet test`

You should see output similar, but not exactly like:
```
Build started, please wait...
Build completed.

Test run for /home/user/Documents/SigningFramework/Tests/bin/Debug/netcoreapp2.0/CryptLink.SigningFrameworkTests.dll(.NETCoreApp,Version=v2.0)
Microsoft (R) Test Execution Command Line Tool Version 15.5.0
Copyright (c) Microsoft Corporation.  All rights reserved.

Starting test execution, please wait...
NUnit Adapter 3.10.0.21: Test execution started
Running all tests in /home/user/Documents/SigningFramework/Tests/bin/Debug/netcoreapp2.0/CryptLink.SigningFrameworkTests.dll
NUnit3TestExecutor converted 23 of 23 NUnit test cases
NUnit Adapter 3.10.0.21: Test execution complete

Total tests: 23. Passed: 23. Failed: 0. Skipped: 0.

```
