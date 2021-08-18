# PingID Windows Login Passwordless Configuration Script

This script will help you configure your PingOne environment and your Active Directory Domain Controller for using PingID Windows Login Passwordless.
Read full documentation [here]http://link.to.docs

This script was built to help speed up PoCs and test/staging environments for qualifying PingID Windows Login Passwordless. For production rollout, please avoid using this script and perform the configurations manually, according to the documentation.

## Prerequisites

1. PingOne with PingID Enviornement 
2. PingFederate with PingOne provisioner configured
3. Active Directory Domain Controller with Administrator privileges
3. PingOne access token

## Usage

:warning: **Use with cautious**: This script modifies your Domain Controller, don't use it in production environments!
1. Download and run the script from an Administrator Powershell command prompt.
3. Run the script and follow the instructions.
4. (Optional) User the `-Debug` flag to get debug level output.
