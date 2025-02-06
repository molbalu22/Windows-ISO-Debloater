# Windows-ISO-Debloater

![Stars](https://img.shields.io/github/stars/itsNileshHere/Windows-ISO-Debloater?style=for-the-badge)
[![Version](https://img.shields.io/github/v/release/itsNileshHere/Windows-ISO-Debloater?color=%230567ff&label=Latest%20Release&style=for-the-badge)](https://github.com/itsNileshHere/Windows-ISO-Debloater/releases/latest)

An easy-to-use and customizable PowerShell script designed to optimize and debloat Windows ISO by removing unnecessary apps & components. Helps to create lightweight, clean ISOs for streamlined installations. Ideal for improved system performance and full control over Windows installation customization.

## 🧪 Tested Versions

The script has been tested with:

- **Windows 10**: Version 22H2 (Build 19045.3757)
- **Windows 11**: Version 24H2 (Build 26100.1742)

⚠️ **Should work with other versions too**

## 🚀 How to Use

1. Launch PowerShell as **ADMINISTRATOR** and execute the following commands
```{powershell}
Set-ExecutionPolicy -Scope Process Unrestricted -Force
iwr -useb https://itsnileshhere.github.io/Windows-ISO-Debloater/download.ps1 | iex
```
💡 *Alternatively, you can manually download the script from [here](https://github.com/itsNileshHere/Windows-ISO-Debloater/releases/latest) and execute it using PowerShell with **ADMINISTRATOR** privileges.*

2. Select Windows ISO from the dialogue. Follow the instructions.
3. The ISO will be generated in the same directory where the script is located.
4. To whitelist a package, simply comment out its name in the script.

## 🛠️ Customization Options

Package removal can be customized by modifying the following sections of the script:

- Packages to remove
- Features to remove
- Registry tweaks

## ⚙️ Using Oscdimg
The script downloads "oscdimg.exe", used to generate the ISO, from Microsoft's website. If you have any doubts, you can download it using the following steps:

1. Download the "Windows ADK" Package from [Microsoft](https://learn.microsoft.com/en-us/windows-hardware/get-started/adk-install).
2. Run the setup. During installation, only check the "Deployment Tools" option and continue the installation.
3. After installing, navigate to "C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit\Deployment Tools\amd64\Oscdimg". The "oscdimg.exe" file will be located there.
4. Copy the file and paste it alongside the script."

## 🌟 Credits
1. [tiny11builder](https://github.com/ntdevlabs/tiny11builder) for idea 
2. [Winaero](https://winaero.com/) for a bunch of Registry Tweaks

---

⚠️ **Note:** This script modifies the Windows ISO. Use it at your own risk.

