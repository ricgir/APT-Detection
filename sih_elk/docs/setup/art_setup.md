# Atomic Red Team Setup and Execution Guide for Windows


## Introduction
**Atomic Red Team** is an open-source library of tests mapped to the MITRE ATT&CK framework, used to safely simulate adversary behavior. This guide covers its installation and execution on a Windows VM.

## Prerequisites
Before you begin, ensure your Windows VM meets the following requirements:

* **Administrator Access**: You must be able to run commands with administrative  - privileges.
* **PowerShell**: Windows PowerShell 5.1 or later is required. This is installed by default on modern Windows versions (Windows 10/11, Server 2016+).
* **Internet Connection**: Required for the initial download and installation of the framework and atomic tests.

## Installation and Setup

The installation process involves setting up the PowerShell execution policy, installing the framework module, and downloading the library of atomic tests.

### Open PowerShell as an Administrator

1. Click the Start Menu.
2. Type PowerShell.
3. Right-click on Windows PowerShell and select Run as administrator.

### Set the PowerShell Execution Policy

This command lowers the security policy for the current session to allow locally-run scripts, which is necessary to install and run the Atomic Red Team framework.

In the administrative PowerShell window, run the following command:

`Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser-Force`

### Install the Atomic Red Team PowerShell Module

This command downloads and installs the core execution engine from the official PowerShell Gallery.

Run the following command. When prompted to install from an untrusted repository, type `Y`and press Enter.


`Install-Module -Name AtomicRedTeam -Scope CurrentUser-Force`


### Import the Module and Download Atomics

After installing the engine, this step loads its commands into your PowerShell session and downloads the actual test files ("atomics") from the official GitHub repository.

Run these two commands in sequence:

**1. Import the module**:

`Import-Module AtomicRedTeam`

**2. Download the atomic tests**:

`Install-AtomicRedTeam -getAtomics`

This will download the tests to your local machine, typically into the `C:\AtomicRedTeam` directory.
You have now successfully installed Atomic Red Team!

## Executing Atomic Tests 

With the framework installed, you can now simulate adversary techniques. The primary command you will use is Invoke-AtomicTest.

### 1. List Available Tests for a Technique

Before running an attack, it's best to see what specific tests are available for a given MITRE ATT&CK technique. We'll use `T1059.001: Command and Scripting Interpreter: PowerShell` as an example.

Run the following command to see a brief list of available tests for this technique:

`Invoke-AtomicTest T1059.001 -ShowDetailsBrief`

You will see an output listing the different atomic tests available, each with a unique test number, name, and supported platform.

### 2. Check for Test Prerequisites

Some tests require specific software or configurations to be in place before they can run. This command checks for those dependencies.

Let's check the prerequisites for `T1548.002: Abuse Elevation Control Mechanism: Bypass User Account Control`:

`Invoke-AtomicTest T1548.002 -GetPrereqs`

If any prerequisites are missing, the framework will provide commands to help you install or configure them.

### 3. Run a Specific Atomic Test

This is the core command that executes the simulated attack. We will run a test for `T1003.001: OS Credential Dumping: LSASS Memory`, which simulates an attacker dumping credentials from memory.

Run the following command:

`Invoke-AtomicTest T1003.001`

The framework will execute the test defined in the T1003.001 YAML file. You will see output describing the command being run. If you have a security tool (like Sysmon or an EDR) running, this is the action it should detect and alert on.

### 4. Clean Up After a Test

Many tests have corresponding cleanup commands to revert any changes made to the system, such as removing created files or registry keys.
To revert the changes made by the previous test (if any), run the same command with the -Cleanup flag:

`Invoke-AtomicTest T1003.001 -Cleanup`

This ensures your VM is returned to its original state.
