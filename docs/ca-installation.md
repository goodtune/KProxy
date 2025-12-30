# KProxy Root CA Installation Guide

For KProxy to intercept and inspect HTTPS traffic, client devices must trust the KProxy root Certificate Authority (CA). This guide provides step-by-step instructions for installing the root CA certificate on various platforms.

---

## ⚠️ CRITICAL SECURITY WARNINGS

**READ THIS BEFORE PROCEEDING**

Installing a root CA certificate grants **significant trust** to the certificate authority. Understand the risks:

### 🔴 What Can Go Wrong

**If the private key (`root-ca.key`) is compromised:**
- ❌ **Attacker can impersonate ANY website** for devices trusting your CA
- ❌ **All HTTPS traffic can be intercepted and decrypted** by the attacker
- ❌ **Banking, email, passwords - everything is vulnerable**
- ❌ **Certificate warnings will NOT appear** because devices trust the attacker's certificates

**If you install someone else's CA certificate:**
- ❌ **That person can monitor ALL your HTTPS traffic**
- ❌ **They can see passwords, credit cards, personal data**
- ❌ **You will have NO indication this is happening**

### ✅ Safety Requirements

**ONLY proceed if:**
1. ✅ **You generated this CA yourself** with `make generate-ca`
2. ✅ **The KProxy server is under YOUR physical control**
3. ✅ **The private key (`/etc/kproxy/ca/root-ca.key`) has NEVER left the server**
4. ✅ **You understand you are intercepting your own traffic**
5. ✅ **You only install on devices YOU own or have permission to monitor**

### 🔒 Security Best Practices

**Protect the private key:**
```bash
# Set restrictive permissions
sudo chmod 600 /etc/kproxy/ca/root-ca.key
sudo chown root:root /etc/kproxy/ca/root-ca.key

# Secure the CA directory
sudo chmod 700 /etc/kproxy/ca
```

**Backup securely:**
```bash
# Create encrypted backup
sudo tar czf kproxy-ca-backup.tar.gz /etc/kproxy/ca
# Store on encrypted USB or secure offline storage
# NEVER store in cloud without encryption
```

**Limit scope:**
- ✅ Only install on devices you control
- ✅ Use `bypass_domains` for banking/healthcare in policies
- ✅ Remove from devices you sell or give away
- ✅ Rotate the CA periodically (annually)

**NEVER:**
- ❌ Share your CA certificate with friends/family for their networks (they should generate their own)
- ❌ Upload the private key (`.key` file) anywhere
- ❌ Install a CA from an untrusted source
- ❌ Use KProxy on devices you don't own without explicit permission

### ⚖️ Legal & Ethical Considerations

- **Only monitor networks and devices you own or have explicit permission to monitor**
- **Inform users that traffic is being monitored** (especially minors - parental controls are legal, but deception is not)
- **Comply with applicable laws** regarding interception and data privacy (GDPR, COPPA, wiretapping laws, etc.)
- **Respect privacy** - even with permission, don't abuse monitoring capabilities

**This is a tool for legitimate parental controls and network management. Misuse can violate laws and trust.**

---

## Table of Contents

- [Overview](#overview)
- [Obtaining the Root CA Certificate](#obtaining-the-root-ca-certificate)
- [Windows](#windows)
- [macOS](#macos)
- [Linux](#linux)
- [iOS (iPhone/iPad)](#ios-iphoneipad)
- [Android](#android)
- [Chrome OS / Chromebook](#chrome-os--chromebook)
- [Firefox (All Platforms)](#firefox-all-platforms)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Removing the CA Certificate](#removing-the-ca-certificate)

---

## Overview

### Why Install the CA Certificate?

KProxy intercepts HTTPS traffic by acting as a "man-in-the-middle" proxy. To do this securely:

1. **KProxy generates its own CA** (when you run `make generate-ca`)
2. **For each HTTPS site**, KProxy generates a certificate on-the-fly signed by this CA
3. **Browsers check** if they trust the certificate
4. **Without installing the CA**, browsers show scary security warnings
5. **After installing the CA**, browsers trust KProxy's certificates

### What Gets Installed?

**File:** `/etc/kproxy/ca/root-ca.crt`

This is a public certificate (not a secret). It tells your device: "Trust certificates signed by KProxy."

**Important:** Keep `/etc/kproxy/ca/root-ca.key` (private key) **SECRET**. Never share or install the `.key` file on client devices.

### Do I Need to Do This for Every Device?

Yes. Each device that will use KProxy as a proxy needs to trust the root CA:
- Computers (Windows, Mac, Linux)
- Phones and tablets (iOS, Android)
- Chromebooks
- Smart TVs (if configurable)

---

## Obtaining the Root CA Certificate

### Option 1: Copy from KProxy Server

```bash
# On KProxy server
sudo cat /etc/kproxy/ca/root-ca.crt

# Copy file to client device via SCP
scp user@kproxy-server:/etc/kproxy/ca/root-ca.crt ~/Downloads/
```

### Option 2: Host on Web Server (Temporary)

For easy installation on mobile devices:

```bash
# On KProxy server, start temporary web server
cd /etc/kproxy/ca
python3 -m http.server 8000

# On client device, navigate to:
http://kproxy-server-ip:8000/root-ca.crt
```

**Security Note:** Stop the web server after installing certificates (`Ctrl+C`). Don't leave it running.

### Option 3: Email or Cloud Storage

Email the certificate to yourself, or upload to Dropbox/Google Drive and download on the target device.

---

## Windows

### Command Line Installation (PowerShell)

Run as Administrator:

```powershell
# Import certificate to Local Machine Trusted Root store (all users)
Import-Certificate -FilePath "C:\path\to\root-ca.crt" -CertStoreLocation Cert:\LocalMachine\Root

# OR import for current user only
Import-Certificate -FilePath "C:\path\to\root-ca.crt" -CertStoreLocation Cert:\CurrentUser\Root
```

**Restart your browser** (Chrome, Edge, etc.) after installation.

### GUI Alternatives

If you prefer graphical installation, Windows provides several methods:
- **Certificate Manager UI**: Right-click `.crt` file → Install Certificate
- **Microsoft Management Console (MMC)**: `mmc.exe` with Certificates snap-in
- **Internet Options**: Control Panel → Internet Options → Content → Certificates

Search for "Windows install root certificate" for detailed GUI instructions.

---

## macOS

### Command Line Installation

```bash
# Install to System keychain (all users - requires sudo)
sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain root-ca.crt

# OR install to user keychain (current user only)
security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain root-ca.crt
```

**Restart your browser** (Safari, Chrome, Firefox) after installation.

**Note:** Safari and Chrome use the macOS keychain. Firefox uses its own certificate store (see [Firefox section](#firefox-all-platforms)).

### GUI Alternative

If you prefer graphical installation:
- **Keychain Access**: Double-click the `.crt` file, add to keychain, then set trust to "Always Trust"

Search for "macOS install root certificate Keychain Access" for detailed GUI instructions.

---

## Linux

### Ubuntu / Debian / Mint

```bash
# Copy certificate to CA certificates directory
sudo cp root-ca.crt /usr/local/share/ca-certificates/kproxy-root-ca.crt

# Update CA trust store
sudo update-ca-certificates

# Verify installation
ls /etc/ssl/certs | grep kproxy
```

**Output:**
```
Adding debian:kproxy-root-ca.pem
1 added, 0 removed; done.
```

**Restart applications** that use HTTPS (browsers, curl, wget, etc.)

### Fedora / RHEL / CentOS

```bash
# Copy certificate to CA trust source
sudo cp root-ca.crt /etc/pki/ca-trust/source/anchors/kproxy-root-ca.crt

# Update CA trust
sudo update-ca-trust

# Verify
trust list | grep -i kproxy
```

### Arch Linux

```bash
# Copy certificate
sudo cp root-ca.crt /etc/ca-certificates/trust-source/anchors/kproxy-root-ca.crt

# Update trust store
sudo trust extract-compat

# Verify
trust list | grep -i kproxy
```

### Alpine Linux

```bash
# Copy certificate
sudo cp root-ca.crt /usr/local/share/ca-certificates/kproxy-root-ca.crt

# Update certificates
sudo update-ca-certificates

# Verify
ls /etc/ssl/certs | grep kproxy
```

**Note:** Chrome and Chromium on Linux use the system certificate store. Firefox uses its own (see [Firefox section](#firefox-all-platforms)).

---

## iOS (iPhone/iPad)

### Installation Steps

1. **Get the certificate onto your iPhone/iPad:**

   **Option A: Email**
   - Email `root-ca.crt` to yourself
   - Open Mail app on iOS device
   - Tap the attachment

   **Option B: AirDrop** (from Mac)
   - Right-click `root-ca.crt` → **Share** → **AirDrop**
   - Select your iPhone/iPad

   **Option C: Web Server**
   - Host certificate on web server (see [Obtaining the Certificate](#obtaining-the-root-ca-certificate))
   - Open Safari on iOS → Navigate to `http://kproxy-server-ip:8000/root-ca.crt`

2. **Install Profile:**

   You'll see: **"Profile Downloaded"**

   - Tap **"Close"**

3. **Open Settings** → **General** → **VPN & Device Management** (or **Profiles**)

4. **Tap the profile** (named after your certificate, e.g., "KProxy Root CA")

5. **Tap "Install"** (top-right)

6. **Enter your passcode** (if prompted)

7. **Tap "Install"** again (warning screen)

8. **Tap "Install"** once more (confirmation)

9. **Tap "Done"**

### Enable Full Trust (Critical Step!)

**iOS requires an additional step to fully trust the certificate:**

1. **Settings** → **General** → **About** → **Certificate Trust Settings**

2. **Enable full trust** for the KProxy Root CA:

   Toggle the switch to **ON** (green)

3. **Tap "Continue"** on the warning dialog

### Verification

1. Open **Safari**
2. Navigate to any HTTPS site (e.g., `https://example.com`)
3. **Should load without warnings**

---

## Android

Android certificate installation varies by version and manufacturer. These instructions work for most devices.

### Android 11+ (User Certificate)

**Note:** Android 11+ requires apps to opt-in to trusting user certificates. System apps and browsers typically work, but some apps may not.

1. **Copy `root-ca.crt` to your Android device:**
   - Via USB
   - Via cloud storage (Google Drive, Dropbox)
   - Via email
   - Via web server

2. **Open Settings** → **Security** (or **Security & Location**)

3. **Tap "Encryption & credentials"** (or **"Advanced" → "Encryption & credentials"**)

4. **Tap "Install a certificate"** (or **"Install from storage"**)

5. **Select "CA certificate"** (not VPN & app user certificate)

6. **Warning dialog:**

   "Installing a CA certificate allows monitoring of your encrypted network traffic"

   **Tap "Install anyway"**

7. **Navigate to the certificate file** → **Select `root-ca.crt`**

8. **Enter PIN/password** if prompted

9. **Certificate installed!** You may see a notification: "Network may be monitored"

### Android 7-10 (User Certificate)

1. **Settings** → **Security** → **Install from storage** (or **"Install certificates from SD card"**)

2. **Select "CA certificate"**

3. **Navigate to the certificate** → Tap it

4. **Name the certificate** (e.g., "KProxy Root CA") → **OK**

### Android 13+ (System Certificate - Root Required)

For full compatibility with all apps (requires rooted device):

```bash
# Connect via ADB
adb root
adb remount

# Calculate certificate hash
openssl x509 -inform PEM -subject_hash_old -in root-ca.crt | head -1
# Example output: 5ed36f99

# Copy certificate with hash name
adb push root-ca.crt /system/etc/security/cacerts/5ed36f99.0

# Set permissions
adb shell chmod 644 /system/etc/security/cacerts/5ed36f99.0

# Reboot
adb reboot
```

**This is advanced and requires root access.** Most users should use the user certificate method.

### Verification

1. Open **Chrome** or **Firefox**
2. Navigate to `https://example.com`
3. **Should load without warnings**

**Note:** Some apps (banking apps, corporate apps) may not trust user certificates on Android 11+ for security reasons.

---

## Chrome OS / Chromebook

### Installation Steps

1. **Copy `root-ca.crt` to your Chromebook** (via Google Drive, USB, etc.)

2. **Open Chrome browser** → **Settings** (or `chrome://settings`)

3. **Search for "certificates"** or navigate to:
   - **Privacy and security** → **Security** → **Manage certificates**

4. **Click "Authorities" tab**

5. **Click "Import"**

6. **Select `root-ca.crt`** → **Open**

7. **Check all trust options:**
   - ✅ Trust this certificate for identifying websites
   - ✅ Trust this certificate for identifying email users
   - ✅ Trust this certificate for identifying software makers

8. **Click "OK"**

9. **Restart Chrome**

### Verification

1. Navigate to `https://example.com`
2. **Should load without warnings**

---

## Firefox (All Platforms)

Firefox uses its own certificate store, separate from the operating system. You must install the CA in Firefox even if you've installed it system-wide.

### Installation Steps

1. **Open Firefox**

2. **Menu** → **Settings** (or **Preferences**)

3. **Privacy & Security** (left sidebar)

4. **Scroll to "Certificates"** section → Click **"View Certificates"**

5. **Click "Authorities" tab**

6. **Click "Import"**

7. **Select `root-ca.crt`** → **Open**

8. **Check trust options:**
   - ✅ Trust this CA to identify websites
   - ✅ Trust this CA to identify email users (optional)

9. **Click "OK"**

10. **Restart Firefox**

### Verification

1. Navigate to `https://example.com`
2. Click the **padlock icon** → **Connection secure**
3. **Certificate should show KProxy as issuer**

---

## Verification

After installation, verify the certificate is trusted:

### Check HTTPS Sites Load

1. Navigate to any HTTPS site (e.g., `https://www.google.com`)
2. **Should load without warnings**
3. **Should NOT see:**
   - "Your connection is not private"
   - "NET::ERR_CERT_AUTHORITY_INVALID"
   - "Security certificate not trusted"

### Check Certificate Details

**Chrome/Edge:**
1. Navigate to an HTTPS site
2. Click the **padlock icon** → **Certificate**
3. **Issuer should show:** Your KProxy CA name

**Firefox:**
1. Navigate to an HTTPS site
2. Click the **padlock icon** → **Connection secure** → **More information**
3. **View Certificate** → Check **Issued by**

**Safari (macOS):**
1. Navigate to an HTTPS site
2. Click the **padlock icon** → **Show Certificate**
3. **Issued by** should show your KProxy CA

### Command-Line Verification

**Linux/macOS:**
```bash
# Test with curl
curl -v https://www.google.com

# Should show successful SSL handshake
# Should NOT show certificate verification errors
```

**Windows PowerShell:**
```powershell
Invoke-WebRequest -Uri https://www.google.com -Verbose

# Should complete without certificate errors
```

---

## Troubleshooting

### Certificate Installed but Sites Still Show Warnings

**Possible causes:**

1. **Browser wasn't restarted** → Restart browser completely (close all windows)

2. **Firefox on Linux/macOS** → Firefox uses its own store, install separately (see [Firefox section](#firefox-all-platforms))

3. **Wrong certificate store:**
   - Windows: Must be in **"Trusted Root Certification Authorities"** (not "Intermediate" or "Personal")
   - macOS: Must be set to **"Always Trust"**
   - iOS: Must enable **"Certificate Trust Settings"** (second step)

4. **Certificate expired** → Regenerate CA: `sudo make generate-ca`

5. **Certificate file corrupted** → Re-download from KProxy server

### "Network May Be Monitored" Warning (Android)

This is **normal** for user-installed CA certificates on Android. It's a security warning that a CA has been added.

**To remove the warning:** Remove the certificate (see [Removing the CA](#removing-the-ca-certificate))

**Note:** The warning appears even for legitimate uses like KProxy.

### iOS Shows "Not Trusted"

**Did you complete both steps?**
1. Install profile (**Settings → General → VPN & Device Management**)
2. Enable trust (**Settings → General → About → Certificate Trust Settings**)

**Both steps are required!**

### macOS Shows "This certificate is not trusted"

1. Open **Keychain Access**
2. Search for the KProxy certificate
3. **Double-click** → **Trust** section
4. Set **"When using this certificate"** to **"Always Trust"**
5. Close window → Enter password

### Corporate/Managed Devices

Some corporate environments prevent installing custom CA certificates. Check with your IT department.

---

## Security Considerations

### Why This is Safe (When Done Right)

✅ **You control the CA:** The private key stays on your KProxy server
✅ **Limited scope:** Only devices you install it on are affected
✅ **Revocable:** You can remove the certificate anytime
✅ **Transparent:** You know exactly what traffic is being inspected

### Risks to Be Aware Of

⚠️ **Private key security:**
- **Keep `/etc/kproxy/ca/root-ca.key` secure** (600 permissions, root-only access)
- If someone gets this file, they can impersonate any HTTPS site for devices that trust your CA

⚠️ **Trust is absolute:**
- Devices trust **any certificate** signed by your CA
- If your KProxy server is compromised, an attacker can MITM your traffic

⚠️ **Don't share the CA:**
- Don't install your CA on devices you don't own
- Don't give the CA to friends/family for their own networks (generate their own)

### Best Practices

1. **Strong KProxy server security:**
   ```bash
   # Secure private key
   sudo chmod 600 /etc/kproxy/ca/root-ca.key
   sudo chown root:root /etc/kproxy/ca/root-ca.key

   # Secure private key directory
   sudo chmod 700 /etc/kproxy/ca
   ```

2. **Backup the CA:**
   ```bash
   # Backup both cert and key (store securely!)
   sudo tar czf kproxy-ca-backup.tar.gz /etc/kproxy/ca
   # Store backup on encrypted USB or secure cloud storage
   ```

3. **Bypass sensitive sites:**
   - Add banking sites to `global_bypass_domains` in your policy
   - See [Policy Tutorial - Step 6](policy-tutorial.md#step-6-bypass-banking-sites)

4. **Rotate CA periodically:**
   ```bash
   # Regenerate CA (e.g., annually)
   sudo make generate-ca

   # Then reinstall on all devices
   ```

5. **Remove from devices you no longer own:**
   - Before selling/giving away a device, remove the CA certificate

---

## Removing the CA Certificate

If you no longer use KProxy or want to remove the certificate:

### Windows

1. **Win+R** → `certmgr.msc`
2. **Trusted Root Certification Authorities** → **Certificates**
3. **Find the KProxy certificate** → **Right-click** → **Delete**

### macOS

1. **Keychain Access** → Search for KProxy certificate
2. **Right-click** → **Delete**
3. **Enter password** to confirm

### Linux (Ubuntu/Debian)

```bash
sudo rm /usr/local/share/ca-certificates/kproxy-root-ca.crt
sudo update-ca-certificates --fresh
```

### Linux (Fedora/RHEL)

```bash
sudo rm /etc/pki/ca-trust/source/anchors/kproxy-root-ca.crt
sudo update-ca-trust
```

### iOS

1. **Settings** → **General** → **VPN & Device Management** → **KProxy Root CA**
2. **Remove Profile** → **Enter passcode** → **Remove**

### Android

1. **Settings** → **Security** → **Encryption & credentials** → **User credentials**
2. **Tap the KProxy certificate** → **Remove**

### Firefox

1. **Settings** → **Privacy & Security** → **View Certificates**
2. **Authorities** tab → Find KProxy certificate
3. **Delete or Distrust**

---

## Additional Resources

- **[KProxy Documentation](README.md)** - Main documentation
- **[Policy Tutorial](policy-tutorial.md)** - Configure access rules
- **[OpenSSL Certificate Commands](https://www.openssl.org/docs/)** - Advanced certificate management

## Support

If you encounter issues:

1. Check the [Troubleshooting](#troubleshooting) section
2. Verify certificate is in correct store location
3. Check KProxy logs: `sudo journalctl -u kproxy -f`
4. Open an issue on GitHub with details

---

**Remember:** Installing a root CA certificate grants **significant trust**. Only install certificates from sources you control and trust completely. For KProxy, this means you should generate and manage your own CA, never download a CA from an untrusted source.
