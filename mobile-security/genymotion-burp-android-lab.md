# Building an Android Pentesting Lab on a Windows Host That Already Runs VMware

**What this is:** a record of setting up Genymotion + Burp Suite for mobile traffic interception, written around the things that broke rather than the things that worked. The official documentation covers the happy path well. It does not cover what happens when you already have a hypervisor installed, when Windows Firewall silently drops your diagnostic traffic, or when Android ignores a certificate without telling you why.

**Environment:** Windows 11 (build 26200), 16 GB RAM, VMware Workstation already running a Kali VM on VMnet8/NAT (192.168.31.129), a Windows Server 2022 DC, and Metasploitable2.

**Result:** Genymotion Desktop 3.10.0 running Android 9.0 (API 28, rooted), ADB connected over the host-only network, Burp Suite Community intercepting and decrypting HTTPS from the device.

---

## Architectural decision: where things run

Three constraints drove the whole layout.

**Genymotion cannot run inside a VM.** Genymotion's own requirements state that virtual environments — VM, Docker, VPS — are not supported. It has to go on the host. So the tempting idea of "install it inside Kali, keep everything in one place" is a dead end before it starts.

**Kali is not an officially supported distro for Genymotion either.** Only Ubuntu LTS, Debian Stable, and Fedora Workstation are.

**Two type-2 hypervisors should not run VMs simultaneously.** VMware Workstation and VirtualBox can be installed side by side, but they compete for VT-x when both have VMs running. The practical rule became: close VMware entirely before launching Genymotion.

That left Burp with two possible homes. Running it on Kali would have meant VMware and VirtualBox live at the same time, plus a routing problem between two isolated private networks, plus memory pressure (Windows ~4 GB + Kali 5 GB + Android 2 GB + Burp's JVM on a 16 GB machine). Running Burp on the Windows host meant Kali didn't need to be running at all. Host it was.

---

## Problem 1: Hyper-V was running even though Hyper-V was disabled

Genymotion on Windows uses VirtualBox by default, and VirtualBox needs direct access to VT-x. If the Hyper-V hypervisor is loaded at boot, it owns VT-x exclusively and VirtualBox falls back to software virtualization — which produces DHCP failures, multi-minute boots, and crashes that look like Genymotion bugs.

Checked the obvious place first. In `optionalfeatures`, every relevant box was **already unchecked**: Hyper-V and both sub-features, Virtual Machine Platform, Windows Hypervisor Platform, Windows Sandbox, WSL, Containers.

Turned off Memory Integrity under Windows Security → Device security → Core isolation. Rebooted. Then:

```
systeminfo
```

```
Virtualization-based security: Status: Running
Hyper-V Requirements: A hypervisor has been detected.
                      Features required for Hyper-V will not be displayed.
```

Still running. Notably, `Services Configured:` and `Services Running:` were both **empty** — so VBS was up but doing nothing. The hypervisor was being launched at boot regardless of which features requested it.

The fix was at the boot loader, not the feature list:

```cmd
bcdedit /set hypervisorlaunchtype off

reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" ^
  /v EnableVirtualizationBasedSecurity /t REG_DWORD /d 0 /f

reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" ^
  /v Enabled /t REG_DWORD /d 0 /f
```

After a reboot:

```
Virtualization-based security: Status: Not enabled
Hyper-V Requirements: VM Monitor Mode Extensions: Yes
                      Virtualization Enabled In Firmware: Yes
                      Second Level Address Translation: Yes
                      Data Execution Prevention Available: Yes
```

### Gotcha: elevation

The first attempt at `bcdedit` returned **Access denied**. The prompt was running as the user account named `Admin`, which is not the same as running elevated. The tell is the working directory: an elevated Command Prompt opens at `C:\Windows\System32`, an unelevated one at `C:\Users\<name>`. `systeminfo` needs no elevation, which is why the diagnostic ran fine and the fix didn't.

### Security trade-off, stated honestly

Memory Integrity (HVCI) defends against BYOVD attacks — loading a legitimately signed but vulnerable driver to get kernel execution, which is how a lot of ransomware disables EDR. Turning it off removes that layer.

Two things make it an acceptable trade rather than a careless one. It only matters *after* something already has administrator on the machine; it is defence in depth, not a perimeter control. And it is a toggle, not a one-way door:

```cmd
bcdedit /set hypervisorlaunchtype auto
```

plus a reboot restores it. Re-enable when the Android work is done.

Side benefit: with the hypervisor gone, VMware Workstation also gets direct VT-x instead of going through the Windows Hypervisor Platform, so the existing lab VMs got faster.

---

## Problem 2: resource defaults sized for a different machine

Installed via `genymotion-3.10.0-vbox.exe` — the bundled installer that ships the VirtualBox version Genymotion is tested against (7.2.6 in this case). The non-bundled installer assumes you already have VirtualBox, which invites version-mismatch problems.

The device creation wizard defaulted to:

| Setting | Default | Changed to | Why |
|---|---|---|---|
| Android image | 15.0.0 (API 35) | **9.0 (API 28)** | see below |
| Processors | 8 | **2** | 8 = every core on the host |
| Memory | 8192 MB | **2048 MB** | 8 GB = half the host's RAM |
| Hardware profile | Genymotion Phone (570×1230, 220dpi) | unchanged | low res reduces OpenGL load |

**On the Android version.** API 35 is the worst choice for a pentesting lab even though it's newest. From Android 7 onward apps don't trust user-installed CA certificates, and modern versions harden `/system` further, tighten pinning behaviour, and break compatibility with a lot of Frida and objection tooling and with older target APKs. Android 9 is old enough to cooperate and new enough to run current apps.

Genymotion's Android 9 image also reports **"This Android version is always in root mode"** — permanently rooted, no toggle. That is what makes the system-trust-store approach possible.

One detail to remember: the image architecture is **x86, not x86_64**. ARM-only APKs won't install without a translation layer, and `frida-server` must be the x86 build. The resulting errors are cryptic if you don't know this up front.

---

## Problem 3: the ping that lied

Device booted and reported its ADB endpoint in the window title: `192.168.167.101:5555`.

`ipconfig` on the host showed two VirtualBox adapters:

- `192.168.56.1` — VirtualBox's default host-only network, unused
- `192.168.167.2` — the adapter Genymotion actually placed the device on

I had assumed the gateway would be `.1`. It was `.2`. Worth checking rather than assuming.

Then this:

```
adb shell ping -c 3 192.168.167.2
3 packets transmitted, 0 received, 100% packet loss
```

The instinct here is to start debugging routing. That would have been wasted time. **Windows Firewall drops inbound ICMP by default on networks it classifies as Public**, and a VirtualBox host-only adapter gets classified exactly that way. A failed ping said nothing about whether TCP to port 8080 would work.

Two rules fixed it, from an elevated prompt:

```cmd
netsh advfirewall firewall add rule name="Burp 8080" dir=in action=allow protocol=TCP localport=8080

netsh advfirewall firewall add rule name="Allow ICMPv4-In" protocol=icmpv4:8,any dir=in action=allow
```

```
3 packets transmitted, 3 received, 0% packet loss
rtt min/avg/max/mdev = 0.448/0.597/0.752/0.127 ms
```

The ICMP rule isn't strictly required for the lab to function — the TCP rule is what matters — but having working ping makes every future diagnosis faster.

### The device has two interfaces, and it matters

```
adb shell ip route
```

```
default via 10.0.3.2 dev radio0
10.0.3.0/24 dev wlan0 proto kernel scope link src 10.0.3.15
10.0.3.0/24 dev radio0 proto kernel scope link src 10.0.3.16
192.168.167.0/24 dev eth0 proto kernel scope link src 192.168.167.101
```

- `eth0` (192.168.167.101) — host-only network, carries ADB
- `wlan0` / `radio0` (10.0.3.x) — VirtualBox NAT, carries internet traffic, holds the default route

So there were two candidate proxy addresses: `192.168.167.2` via eth0, or `10.0.3.2` (the NAT gateway, also the host) via wlan0. The host-only address worked. Knowing both exist means you have a fallback when one doesn't.

---

## Problem 4: Burp's export wrote nothing and said nothing

ADB came from the standalone platform-tools zip (no Android Studio needed), extracted to `C:\platform-tools` and added to PATH:

```cmd
setx PATH "%PATH%;C:\platform-tools"
```

*(PATH changes don't reach already-open terminals — open a fresh one.)*

```
adb devices
192.168.167.101:5555   device
```

Burp Community installed, listener rebound from *Loopback only* to **All interfaces** (the default 127.0.0.1 binding is unreachable from the device), proxy set on the device:

```cmd
adb shell settings put global http_proxy 192.168.167.2:8080
```

HTTP history immediately filled with `/complete/search` calls to google.com — **autocomplete traffic from the Android launcher's search widget**, generated with no user interaction at all. First real observation of the build: a device talks constantly without being asked to.

Then the certificate export failed three different ways.

**Attempt 1 — Burp's export wizard to `C:\burp.der`.** Ran the wizard, typed the path, clicked through. `dir C:\burp.der` → *File Not Found*. Writing to the root of `C:\` requires elevation and Burp was running unelevated. **No error dialog appeared.** The export silently did nothing.

**Attempt 2 — download from the device.** Burp serves its CA at `http://burp` when the proxy is active. The page rendered on the device (proving browser traffic was proxied), tapped "CA Certificate", then:

```
adb shell ls /sdcard/Download/
```

Empty. WebView Browser Tester — the stock browser in the Genymotion image — is a bare test harness, not a full browser, and its download handling silently failed.

**Attempt 3 — fetch it from the host over HTTP.** Burp exposes the same certificate at `/cert` on the listener:

```cmd
curl -o C:\Users\Admin\cacert.der http://127.0.0.1:8080/cert
```

```
100   987  100   987    0     0  18853      0
```

987 bytes, written to a path the user actually owns. `curl` ships with Windows 10/11, so no extra install.

**Lesson:** when a GUI export produces no file and no error, stop re-running the GUI. Find the programmatic path.

---

## Problem 5: `subject_hash_old`, not `subject_hash`

This is the one that silently defeats people.

Android's system trust store requires certificates to be named after the certificate's **subject hash**, with a `.0` extension — `9a5ba575.0`. Android computes that hash at validation time and looks for a file with exactly that name. Wrong name, and the certificate is ignored. No error, no warning, no log entry — HTTPS just keeps failing.

And Android uses the **legacy MD5-based hash**, not OpenSSL's modern default. Generic guides that say `-subject_hash` produce a valid-looking eight-character hex string that is simply the wrong one.

OpenSSL wasn't on PATH in Windows — but **Git Bash ships with it** (3.5.6 here), so no install was needed:

```bash
openssl x509 -inform DER -in cacert.der -out cacert.pem
openssl x509 -inform PEM -subject_hash_old -in cacert.pem | head -1
# 9a5ba575
cp cacert.pem 9a5ba575.0
```

Push it into `/system`, which is mounted read-only by default:

```cmd
adb root
adb remount
adb push C:\Users\Admin\9a5ba575.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/9a5ba575.0
adb reboot
```

`adb root` succeeded immediately (`adbd is already running as root`) because the Android 9 Genymotion image is permanently rooted. `adb remount` made `/system` writable.

**The chmod is not optional.** Android ignores certificates with wrong permissions, and fails silently when it does. Verify after reboot:

```
adb shell ls -l /system/etc/security/cacerts/9a5ba575.0
-rw-r--r--
```

---

## Verification, and a trap in the verification

With Burp running, clicking "Open browser" launches Burp's own embedded Chromium. Requests from it appear in HTTP history over HTTPS and look exactly like success.

They aren't. The User-Agent gives it away:

```
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/151.0.0.0
```

That proves Burp can decrypt TLS. It says nothing about whether **Android** trusts Burp's CA, which is the thing actually being tested.

The real test runs on the device:

```cmd
adb shell am start -a android.intent.action.VIEW -d https://example.com
```

Two conditions for success: the page loads on the device **with no certificate warning**, and the request appears in HTTP history with an Android user-agent. Both held.

---

## Operating notes

| Item | Value |
|---|---|
| Device ADB endpoint | `192.168.167.101:5555` |
| Host-only adapter (proxy target) | `192.168.167.2` |
| Fallback proxy target (NAT gateway) | `10.0.3.2` |
| System cert filename | `9a5ba575.0` |

Set the proxy (does not reliably survive reboots):

```cmd
adb shell settings put global http_proxy 192.168.167.2:8080
```

Clear it:

```cmd
adb shell settings put global http_proxy :0
```

Restore host security when Android work is finished:

```cmd
bcdedit /set hypervisorlaunchtype auto
```

then re-enable Memory Integrity in Windows Security and reboot.

Other standing constraints:

- Close VMware Workstation entirely before launching Genymotion, and vice versa.
- Burp Community cannot save projects — every session starts empty. Export anything worth keeping before closing.
- If HTTPS suddenly breaks with certificate errors after a Genymotion update, re-push `9a5ba575.0`; `/system` changes don't always survive.

---

## What the failures had in common

Four of the five problems shared a pattern: **the system failed silently and the obvious diagnostic was misleading.**

- Hyper-V reported as disabled in the feature list while the hypervisor was still loaded at boot.
- A dead ping implied no route when the route was fine and only ICMP was blocked.
- A certificate export produced no file and no error.
- A wrongly-named certificate is ignored with no log entry, no warning, and no visible difference from a correctly-named one that hasn't taken effect yet.

The habit that gets you through this is refusing to accept a single negative signal as a conclusion. `ping` failing is evidence about ICMP, not about connectivity. A feature checkbox being unchecked is evidence about the checkbox, not about whether the hypervisor is running. Each time, the answer came from finding a second, independent way to ask the same question.
