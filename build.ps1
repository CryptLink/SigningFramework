write-host "dotnet version: " (dotnet --version);

dotnet restore SigningFramework.csproj --verbosity m;
dotnet restore Tests/SigningFrameworkTests.csproj --verbosity m;
dotnet test Tests/SigningFrameworkTests.csproj --logger:"trx;LogFileName=\Results.trx";
      
if ($env:APPVEYOR -eq "True") {
    # upload results to AppVeyor
    $wc = New-Object 'System.Net.WebClient';
    $wc.UploadFile("https://ci.appveyor.com/api/testresults/nunit/$($env:APPVEYOR_JOB_ID)", (Resolve-Path Tests/TestResults/Results.trx));
}