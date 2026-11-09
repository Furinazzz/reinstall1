$ErrorActionPreference = 'Stop'

# Loaded by windows-personalize.ps1. Defining these functions changes no settings.
function Initialize-ReinstallProcessRunner {
    if ('Reinstall.NativeProcess' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Reinstall {
    public static class NativeProcess {
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        struct StartupInfo {
            public int Size; public string Reserved, Desktop, Title;
            public int X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
            public short ShowWindow, ReservedSize;
            public IntPtr ReservedBytes, StdInput, StdOutput, StdError;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct ProcessInfo { public IntPtr Process, Thread; public uint ProcessId, ThreadId; }
        [StructLayout(LayoutKind.Sequential)]
        struct Accounting {
            public long UserTime, KernelTime, PeriodUserTime, PeriodKernelTime;
            public uint PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct BasicLimits {
            public long ProcessTime, JobTime; public uint Flags;
            public UIntPtr MinWorkingSet, MaxWorkingSet; public uint ActiveProcessLimit;
            public UIntPtr Affinity; public uint Priority, Scheduling;
        }
        [StructLayout(LayoutKind.Sequential)]
        struct IoCounters { public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes; }
        [StructLayout(LayoutKind.Sequential)]
        struct ExtendedLimits {
            public BasicLimits Basic; public IoCounters Io;
            public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
        }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern IntPtr CreateJobObject(IntPtr attributes, string name);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref ExtendedLimits limits, int size);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool QueryInformationJobObject(IntPtr job, int infoClass, out Accounting info, int size, IntPtr length);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool TerminateJobObject(IntPtr job, uint code);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool TerminateProcess(IntPtr process, uint code);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError=true)]
        static extern bool GetExitCodeProcess(IntPtr process, out uint code);
        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        static extern bool CreateProcess(string app, StringBuilder command, IntPtr processAttributes,
            IntPtr threadAttributes, bool inheritHandles, uint flags, IntPtr environment,
            string directory, ref StartupInfo startup, out ProcessInfo process);

        // Preserve simple arguments: SFX launchers inspect raw switches before
        // parsing them, and batch payloads may compare %1 without stripping quotes.
        // Use Windows CRT escaping only when an argument actually needs quotes.
        public static string Quote(string value) {
            if (value == null) value = "";
            bool needsQuotes = value.Length == 0;
            foreach (char c in value) {
                if (Char.IsWhiteSpace(c) || c == '"') { needsQuotes = true; break; }
            }
            if (!needsQuotes) return value;
            var result = new StringBuilder("\"");
            int slashes = 0;
            foreach (char c in value) {
                if (c == '\\') { slashes++; continue; }
                if (c == '"') result.Append('\\', slashes * 2 + 1);
                else result.Append('\\', slashes);
                result.Append(c); slashes = 0;
            }
            return result.Append('\\', slashes * 2).Append('"').ToString();
        }
        static void Check(bool success, string action) {
            if (!success) throw new Win32Exception(Marshal.GetLastWin32Error(), action);
        }
        public static int Run(string file, string[] args, string directory, string temp, int timeoutSeconds) {
            IntPtr job = IntPtr.Zero, environment = IntPtr.Zero;
            ProcessInfo process = new ProcessInfo();
            bool assigned = false;
            try {
                job = CreateJobObject(IntPtr.Zero, null);
                Check(job != IntPtr.Zero, "Create process job");
                var limits = new ExtendedLimits();
                limits.Basic.Flags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                Check(SetInformationJobObject(job, 9, ref limits, Marshal.SizeOf(limits)), "Configure process job");
                var variables = new SortedDictionary<string,string>(StringComparer.OrdinalIgnoreCase);
                foreach (DictionaryEntry pair in Environment.GetEnvironmentVariables())
                    variables[(string)pair.Key] = (string)pair.Value;
                variables["TEMP"] = temp; variables["TMP"] = temp;
                var block = new StringBuilder();
                foreach (var pair in variables) block.Append(pair.Key).Append('=').Append(pair.Value).Append('\0');
                block.Append('\0');
                environment = Marshal.StringToHGlobalUni(block.ToString());
                var command = new StringBuilder(Quote(file));
                foreach (string arg in args) command.Append(' ').Append(Quote(arg));
                var startup = new StartupInfo(); startup.Size = Marshal.SizeOf(startup);
                startup.Flags = 1; startup.ShowWindow = 0; // hidden, with a real console
                // Suspend before assigning the job, so short-lived launchers cannot escape tree tracking.
                Check(CreateProcess(file, command, IntPtr.Zero, IntPtr.Zero, false,
                    0x00000414, environment, directory, ref startup, out process), "Start " + file);
                Check(AssignProcessToJobObject(job, process.Process), "Assign process tree to job");
                assigned = true;
                if (ResumeThread(process.Thread) == UInt32.MaxValue) Check(false, "Resume process");
                var elapsed = Stopwatch.StartNew();
                while (true) {
                    Accounting status;
                    Check(QueryInformationJobObject(job, 1, out status, Marshal.SizeOf(typeof(Accounting)), IntPtr.Zero), "Query process tree");
                    if (status.ActiveProcesses == 0) break;
                    if (elapsed.Elapsed.TotalSeconds >= timeoutSeconds) {
                        Check(TerminateJobObject(job, 1460), "Terminate timed out process tree");
                        throw new TimeoutException("Process tree exceeded " + timeoutSeconds + " seconds: " + file);
                    }
                    Thread.Sleep(100);
                }
                uint exitCode;
                Check(GetExitCodeProcess(process.Process, out exitCode), "Read process exit code");
                return unchecked((int)exitCode);
            }
            finally {
                if (process.Process != IntPtr.Zero && !assigned) TerminateProcess(process.Process, 1);
                if (process.Thread != IntPtr.Zero) CloseHandle(process.Thread);
                if (process.Process != IntPtr.Zero) CloseHandle(process.Process);
                if (job != IntPtr.Zero) CloseHandle(job);
                if (environment != IntPtr.Zero) Marshal.FreeHGlobal(environment);
            }
        }
    }
}
'@
}

function Invoke-ReinstallComponentProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $FilePath,
        [string[]] $ArgumentList = @(),
        [Parameter(Mandatory)][string] $WorkingDirectory,
        [ValidateRange(1, 7200)][int] $TimeoutSeconds = 600
    )
    $file = (Get-Item -LiteralPath $FilePath -ErrorAction Stop).FullName
    $directory = (Get-Item -LiteralPath $WorkingDirectory -ErrorAction Stop).FullName
    $temp = Join-Path $directory 'temp'
    New-Item -ItemType Directory -Path $temp -Force -ErrorAction Stop | Out-Null
    Initialize-ReinstallProcessRunner
    return [Reinstall.NativeProcess]::Run($file, $ArgumentList, $directory, $temp, $TimeoutSeconds)
}

function Invoke-ReinstallEdgeRemoval {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $InstallerDirectory,
        [Parameter(Mandatory)][string] $WorkingDirectory
    )
    # Run the supplied unattended tool twice. Wait for each complete process
    # tree before starting the next run; do not inspect removal results.
    for ($attempt = 1; $attempt -le 2; $attempt++) {
        Write-Host "Running Remove-EdgeWeb ($attempt/2)..."
        $exitCode = Invoke-ReinstallComponentProcess -FilePath (Join-Path $InstallerDirectory 'Remove-EdgeWeb.exe') -WorkingDirectory $WorkingDirectory
        if ($exitCode -ne 0) {
            Write-Warning "Remove-EdgeWeb run $attempt returned exit code $exitCode; continuing the scheduled steps."
        }
    }
    Write-Host 'Both Remove-EdgeWeb runs have ended. Continuing to software installation.'
}

function Invoke-ReinstallDefenderRemoval {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string] $InstallerDirectory,
        [Parameter(Mandatory)][string] $WorkingDirectory
    )
    # The expected SFX embeds Script_Run.bat: Y = antivirus + security components.
    # -y is consumed by the 7-Zip SFX, and Y is passed to Script_Run.bat.
    # It schedules shutdown /r /f /t 10, so this must be the final stage.
    # Use a compatible tool release with the same unattended arguments.
    $exitCode = Invoke-ReinstallComponentProcess -FilePath (Join-Path $InstallerDirectory 'DefenderRemover.exe') -ArgumentList @('-y', 'Y') -WorkingDirectory $WorkingDirectory
    if ($exitCode -ne 0) { throw "Defender Remover failed with exit code $exitCode." }
    # SFX exit code only describes the launcher; do not claim removal verified.
    Write-Host 'Defender Remover full-component action returned; it schedules the restart itself.'
}
