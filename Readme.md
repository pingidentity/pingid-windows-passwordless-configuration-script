# PingID Windows Login Passwordless Configuration Script
 
This script will help you configure your PingOne environment and your Active Directory Domain Controller for using PingID Windows Login Passwordless.
Read full documentation [here](https://docs.pingidentity.com/bundle/pingid/page/haa1637494996308.html)

This script was built to help speed up PoCs and test/staging environments for qualifying PingID Windows Login Passwordless. For production rollout, please avoid using this script and perform the configurations manually, according to the documentation.

## Prerequisites

1. PingOne with PingID Enviornement 
2. PingFederate with PingOne provisioner configured
3. Active Directory Domain Controller with Administrator privileges
3. PingOne access token
<!--TODO: Add links to the docs-->
4. Powershell 7 or above

## Usage

:warning: **Use with caution**: This script modifies your Domain Controller, don't use it in production environments!
1. Clone the repository 
2. From Powershell 7 with Administrator privileges, Run `Configure-Passwordless.ps1` and follow the instructions.
4. (Optional) User the `-Debug` flag to get debug level output.
