# Environment Setup Guide

This guide provides step-by-step instructions to configure the complete lab environment required for this project. Following these steps ensures that you have a functional ELK Stack ready to receive and analyze logs for threat detection.


# Pre-installation

This phase involves gathering all the necessary software before starting the installation process.

## Windows 11 Disk Image (ISO)

This is the operating system that will serve as our target endpoint.

- ### Description:

    A Windows 11 ISO file is a complete copy of the Windows 11 installation media, required by the virtual machine manager to install the OS.

- ### Instructions:

    - Navigate to the official [Microsoft Windows 11 Download page](https://www.microsoft.com/software-download/windows11).
    - Under the "Download Windows 11 Disk Image (ISO)" section, select "Windows 11 (multi-edition ISO)".

    - Click "Download", choose your product language, and click "Confirm".
    - Click the "64-bit Download" button to save the ISO file to your computer.

## VirtIO Drivers

These are specialized drivers that boost the performance of your virtual machine.

- ### Description: 

    VirtIO provides a set of high-performance drivers for virtualized hardware, such as network cards and disk controllers. Using them allows the guest OS (Windows) to communicate more efficiently with the host hypervisor (QEMU/KVM), resulting in significantly better I/O performance.

- ### Instructions:

    - Go to the [Proxmox VE Wiki for Windows VirtIO Drivers](https://pve.proxmox.com/wiki/Windows_VirtIO_Drivers).

    - Download the latest stable VirtIO driver ISO file. The direct link is typically named virtio-win-x.x.xxx.iso.

# Installation

This phase covers the setup of the virtualization platform and the installation of the Windows 11 guest OS.

## QEMU/KVM & Virtual Machine Manager

This is the software that will create and run your virtual machine.

- ### Description: 

    **QEMU** is an emulator, and **KVM** (Kernel-based Virtual Machine) is a Linux kernel module that allows the kernel to act as a hypervisor. Together, they provide an efficient, hardware-accelerated virtualization solution. virt-manager provides a user-friendly graphical interface to manage them.

- ### Instructions:

    - **Check for Virtualization Support**: 

        Open a terminal on your Linux host and run egrep -c `'(vmx|svm)' /proc/cpuinfo`. A result greater than 0 means your CPU supports virtualization. Ensure it is enabled in your BIOS/UEFI.

    - **Install Packages** (for Debian/Ubuntu-based systems):

        ```
        sudo apt update
        sudo apt install qemu-kvm libvirt-daemon-system libvirt-clients bridge-utils virt-manager
        ```

    - **Restart and Enable Services**: After installation, restart, enable, and start the virtualization service.

        ```
        sudo systemctl restart libvirt.service
        sudo systemctl enable libvirt.service
        ```

    - It is also a good practice to log out and log back in, or reboot your machine, to ensure all changes are applied.


## Windows 11 VM Creation and Driver Setup

Now you'll create the VM and install Windows along with the performance drivers.

- ### Instructions:

    1. Launch **Virtual Machine Manager** (`virt-manager`) from your applications menu or terminal.

    2. Click the "Create a new virtual machine" icon.

    3. Select "Local install media (ISO image or CDROM)" and click "Forward".

    4. Click "Browse Local" and select the Windows 11 ISO you downloaded. Click "Forward".

    5. Allocate at least 4 GB (4096 MB) of RAM and 2 CPU cores. Click "Forward".

    6. Create a virtual disk of at least 64 GB. Click "Forward".

    7. On the final screen, check the box for "Customize configuration before install" and click "Finish".

    8. In the customization window, click "Add Hardware".

    9. Select "Storage", choose "CDROM device", and click "Manage".

    10. Click "Browse Local" and select the VirtIO driver ISO you downloaded. Click "Finish".

    11. Click **"Begin Installation"**. During the Windows setup, when you reach the "Where do you want to install Windows?" screen, your disk will likely not be visible.

    12. Click **"Load driver"**, then "Browse". Navigate to the VirtIO CD drive, find the amd64\w11 folder inside the viostor directory, and select it. Click "OK".

    13. The storage driver will load, and your virtual disk will appear. You can now proceed with the Windows installation as usual.

    14. After Windows is installed and running, open File Explorer, go to the VirtIO CD drive, and run the virtio-win-guest-tools installer to install all remaining drivers automatically.

# Post-installation

After the Windows VM is running, you will deploy and configure the security agents needed for log collection.

## **1. Enable Group Policy Editor (`gpedit.msc`) and Advanced Logging**

This tool allows you to enable detailed system auditing that isn't on by default.


- **Description**:

    The Group Policy Editor (gpedit.msc) is a Windows administration tool used to configure system and user settings. We will use it to enable Advanced Audit Policies that generate high-value security events, such as detailed process creation logs with command-line arguments. Note: gpedit.msc is not available on Windows Home editions, but can be enabled with a script.

- **Instructions**:

    **1. Enable gpedit.msc (if using Windows Home)**:
    - Open Notepad and paste the following code:

            @echo off
            echo Checking for permissions...
            net session >nul 2>&1
            if %errorlevel% neq 0 (
                echo Administrator permissions required.
                echo Please run this script as an administrator.
                pause
                exit
            )

            echo Enabling Group Policy Editor...
            pushd "%~dp0"

            set "package_path=%SystemRoot%\servicing\Packages"
            set "search_pattern1=Microsoft-Windows-GroupPolicy-ClientTools-Package~*.mum"
            set "search_pattern2=Microsoft-Windows-GroupPolicy-ClientExtensions-Package~*.mum"

            echo Searching for packages...
            dir /b "%package_path%\%search_pattern1%" > gpedit_list.txt
            dir /b "%package_path%\%search_pattern2%" >> gpedit_list.txt

            echo Installing packages...
            for /f %%i in ('findstr /i . gpedit_list.txt 2^>nul') do (
                echo Installing %%i
                dism /online /norestart /add-package:"%package_path%\%%i"
            )

            echo Cleaning up...
            del gpedit_list.txt

            echo Process completed. You can now try running gpedit.msc.
            pause
            


    - Save the file as gpedit-enabler.bat and run it as an Administrator.


    **2. Enable Advanced Audit Policies**:

    - Press Win + R, type gpedit.msc, and press Enter.

    - Navigate to Computer Configuration -> Windows Settings -> Security Settings 
    -> Advanced Audit Policy Configuration -> System Audit Policies.

    - Go to Detailed Tracking and double-click "Audit Process Creation".

    - Check the boxes for both "Success" and "Failure" and click "OK". This will enable logging for Event ID 4688, which includes command-line details.

## **2. Sysmon (System Monitor) Setup**

Sysmon is a powerful tool that provides deep visibility into system activity.

- **Description**: 

    **Sysmon** is a free tool from Microsoft Sysinternals that monitors and logs system activity to the Windows Event Log. It provides highly detailed information about process creation, network connections, file changes, and more, which are invaluable for threat detection.

- **Instructions**:

    1. Download Sysmon from the [Microsoft Sysinternals page](https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon).

    2. Download a trusted, community-vetted configuration file. The [SwiftOnSecurity configuration](https://github.com/SwiftOnSecurity/sysmon-config) is an excellent starting point. Download the sysmonconfig-export.xml file.

    3. Place both the `Sysmon64.exe` executable and the configuration file (`sysmonconfig-export.xml`) in the same directory (e.g., `C:\Sysmon`).

    4. Open PowerShell as an Administrator, navigate to the directory, and run the installation command:

        `.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml`


    5. Sysmon is now installed and actively logging events to `Applications and Services Logs/Microsoft/Windows/Sysmon/Operational`.


## **3. Winlogbeat Setup**

This agent will collect all your logs and send them to your analysis server.

- **Description**: 

    Winlogbeat is a lightweight data shipper from Elastic that is installed on your Windows VM. It tails Windows event logs (including the ones generated by Sysmon), and forwards them to a central Logstash or Elasticsearch server for analysis and visualization.

- **Instructions**:

    1. Download Winlogbeat from the [Elastic downloads page](https://www.elastic.co/downloads/beats/winlogbeat). Unzip the file to a location like `C:\Program Files\Winlogbeat`.

    2. Navigate to the Winlogbeat directory and open the winlogbeat.yml configuration file in a text editor like Notepad++.

    3. Configure the input: Ensure Winlogbeat collects the Sysmon logs.
        
        winlogbeat.event_logs:
        - name: Application
        - name: Security
        - name: System
        - name: Microsoft-Windows-Sysmon/Operational
        ignore_older: 72h
    

    4. Configure the output: Point it to your Logstash or Elasticsearch instance. Replace the IP address accordingly.
        
        `output.logstash:
            hosts: ["192.168.1.100:5044"]`
        

        Example for Elasticsearch (comment out the Logstash section if using this)
        
        `output.elasticsearch:
        hosts: ["192.168.1.100:9200"]`

    5. Save the winlogbeat.yml file.

    6. Open PowerShell as an Administrator, navigate to the Winlogbeat directory, and run the following scripts to install and start the service:
        
        `.\install-service-winlogbeat.ps1
        Start-Service winlogbeat`
        

    7. Winlogbeat is now running as a service and forwarding logs from your Windows 11 VM.



