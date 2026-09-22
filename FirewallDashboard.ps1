#Requires -Version 5.1
<#
    ================================================================
      Windows Firewall Dashboard  (PowerShell + Windows Forms)
    ----------------------------------------------------------------
      Imkoniyatlar:
        - Firewall profillari (Domain/Private/Public) boshqaruvi
        - Qoidalarni ko'rish / yaratish / yoqish / o'chirish
        - Saytlarni bloklash/ruxsat (hosts fayli orqali)
        - Qurilmalarni MAC bo'yicha bloklash (MAC -> IP -> firewall)
        - IP va portlarni bloklash
        - TRAFIK: qaysi dastur/xizmat qancha internet ishlatayotgani (ETW)
        - BUYRUQ KONSOLI: oddiy buyruq yozasiz, kod ishga tushadi

      Ishga tushirish:
        Set-ExecutionPolicy -Scope Process Bypass
        .\FirewallDashboard.ps1
      (Kerak bo'lsa o'zini administrator sifatida qayta ishga tushiradi.)

      MAC bloki haqida eslatma:
        Windows firewall MAC bo'yicha filtrlay olmaydi. Shuning uchun
        MAC tarmoq keshidan (ARP/neighbor) IP'ga o'giriladi va o'sha IP
        bloklanadi. Faqat lokal tarmoqdagi FAOL qurilmalar uchun ishlaydi.
        Qurilmani butun internetdan uzish uchun routerdan foydalaning.
    ================================================================
#>

# --------------------------------------------------------------
#  Admin tekshiruvi + o'z-o'zini elevate qilish
# --------------------------------------------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    try {
        # .ps1 sifatida ishlayaptimi yoki kompilyatsiya qilingan .exe (ps2exe / Bat To Exe) sifatidami?
        $selfPath = if ($PSCommandPath) { $PSCommandPath } else { [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName }
        if ($selfPath -match '\.exe$') {
            # Exe — o'zini administrator sifatida qayta ishga tushiramiz
            Start-Process -FilePath $selfPath -Verb RunAs | Out-Null
        } else {
            # Oddiy skript — PowerShell orqali qayta ishga tushiramiz
            $hostExe = (Get-Process -Id $PID).Path
            Start-Process -FilePath $hostExe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$selfPath`"" -Verb RunAs | Out-Null
        }
    } catch {
        [void][System.Reflection.Assembly]::LoadWithPartialName('System.Windows.Forms')
        [System.Windows.Forms.MessageBox]::Show("Administrator huquqi kerak.","Ruxsat yo'q",'OK','Warning')
    }
    exit
}

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# --------------------------------------------------------------
#  Trafik monitori (ETW: Microsoft-Windows-Kernel-Network)
#  Har bir jarayon bo'yicha TCP + UDP (QUIC) baytlarini sanaydi.
# --------------------------------------------------------------
if (-not ('FwNetMon' -as [type])) {
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Threading;

public class FwNetStat { public int Pid; public long Sent; public long Recv; }

public static class FwNetMon
{
    const string SessionName = "FWDash-NetMon";
    static readonly Guid KernelNetwork = new Guid("7DD42A49-5329-4832-8DFD-43D979153A88");
    const uint EVENT_TRACE_REAL_TIME_MODE = 0x00000100;
    const uint WNODE_FLAG_TRACED_GUID = 0x00020000;
    const uint EVENT_TRACE_CONTROL_STOP = 1;
    const uint PROCESS_TRACE_MODE_REAL_TIME = 0x00000100;
    const uint PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000;
    const int ERROR_ALREADY_EXISTS = 183;
    const ulong INVALID64 = 0xFFFFFFFFFFFFFFFF;
    const ulong INVALID32 = 0x00000000FFFFFFFF;

    [StructLayout(LayoutKind.Sequential)]
    public struct WNODE_HEADER { public uint BufferSize; public uint ProviderId; public ulong HistoricalContext; public long TimeStamp; public Guid Guid; public uint ClientContext; public uint Flags; }

    [StructLayout(LayoutKind.Sequential)]
    public struct EVENT_TRACE_PROPERTIES {
        public WNODE_HEADER Wnode;
        public uint BufferSize, MinimumBuffers, MaximumBuffers, MaximumFileSize, LogFileMode, FlushTimer, EnableFlags;
        public int AgeLimit;
        public uint NumberOfBuffers, FreeBuffers, EventsLost, BuffersWritten, LogBuffersLost, RealTimeBuffersLost;
        public IntPtr LoggerThreadId;
        public uint LogFileNameOffset, LoggerNameOffset;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EVENT_TRACE_HEADER { public ushort Size; public ushort FieldTypeFlags; public uint Version; public uint ThreadId; public uint ProcessId; public long TimeStamp; public Guid Guid; public uint KernelTime; public uint UserTime; }

    [StructLayout(LayoutKind.Sequential)]
    public struct EVENT_TRACE { public EVENT_TRACE_HEADER Header; public uint InstanceId; public uint ParentInstanceId; public Guid ParentGuid; public IntPtr MofData; public uint MofLength; public uint ClientContext; }

    [StructLayout(LayoutKind.Sequential, Size = 172)]
    public struct TIME_ZONE_INFORMATION { public int Bias; }

    [StructLayout(LayoutKind.Sequential)]
    public struct TRACE_LOGFILE_HEADER {
        public uint BufferSize; public uint Version; public uint ProviderVersion; public uint NumberOfProcessors;
        public long EndTime; public uint TimerResolution; public uint MaximumFileSize; public uint LogFileMode; public uint BuffersWritten;
        public Guid LogInstanceGuid; public IntPtr LoggerName; public IntPtr LogFileName;
        public TIME_ZONE_INFORMATION TimeZone;
        public long BootTime; public long PerfFreq; public long StartTime; public uint ReservedFlags; public uint BuffersLost;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct EVENT_TRACE_LOGFILE {
        public IntPtr LogFileName; public IntPtr LoggerName; public long CurrentTime; public uint BuffersRead; public uint ProcessTraceMode;
        public EVENT_TRACE CurrentEvent; public TRACE_LOGFILE_HEADER LogfileHeader;
        public IntPtr BufferCallback; public uint BufferSize; public uint Filled; public uint EventsLost;
        public IntPtr EventRecordCallback; public uint IsKernelTrace; public IntPtr Context;
    }

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    delegate void EventRecordCallbackFn(IntPtr record);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "StartTraceW")]
    static extern int StartTrace(out ulong handle, string name, IntPtr props);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, EntryPoint = "ControlTraceW")]
    static extern int ControlTrace(ulong handle, string name, IntPtr props, uint code);
    [DllImport("advapi32.dll")]
    static extern int EnableTraceEx2(ulong handle, ref Guid provider, uint controlCode, byte level, ulong anyKeyword, ulong allKeyword, uint timeout, IntPtr enableParams);
    [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "OpenTraceW")]
    static extern ulong OpenTrace(ref EVENT_TRACE_LOGFILE logfile);
    [DllImport("advapi32.dll")]
    static extern int ProcessTrace(ulong[] handles, uint count, IntPtr start, IntPtr end);
    [DllImport("advapi32.dll")]
    static extern int CloseTrace(ulong handle);

    static readonly object sync = new object();
    static readonly Dictionary<int, long[]> stats = new Dictionary<int, long[]>();
    static EventRecordCallbackFn callback;
    static ulong traceHandle;
    static IntPtr loggerNamePtr = IntPtr.Zero;
    static volatile bool running;
    static long events;

    public static bool IsRunning { get { return running; } }
    public static long EventCount { get { return Interlocked.Read(ref events); } }

    static IntPtr NewProps()
    {
        int size = Marshal.SizeOf(typeof(EVENT_TRACE_PROPERTIES));
        int total = size + 2048;
        IntPtr buf = Marshal.AllocHGlobal(total);
        Marshal.Copy(new byte[total], 0, buf, total);
        EVENT_TRACE_PROPERTIES p = new EVENT_TRACE_PROPERTIES();
        p.Wnode.BufferSize = (uint)total;
        p.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        p.Wnode.ClientContext = 1;
        p.BufferSize = 64;
        p.MinimumBuffers = 8;
        p.MaximumBuffers = 64;
        p.FlushTimer = 1;
        p.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        p.LoggerNameOffset = (uint)size;
        p.LogFileNameOffset = 0;
        Marshal.StructureToPtr(p, buf, false);
        return buf;
    }

    static void StopSession()
    {
        IntPtr p = NewProps();
        try { ControlTrace(0, SessionName, p, EVENT_TRACE_CONTROL_STOP); }
        finally { Marshal.FreeHGlobal(p); }
    }

    public static string Start()
    {
        lock (sync)
        {
            if (running) return null;
            StopSession();
            ulong h;
            IntPtr props = NewProps();
            try
            {
                int rc = StartTrace(out h, SessionName, props);
                if (rc == ERROR_ALREADY_EXISTS)
                {
                    StopSession();
                    Marshal.FreeHGlobal(props);
                    props = NewProps();
                    rc = StartTrace(out h, SessionName, props);
                }
                if (rc != 0) return "StartTrace xato kodi " + rc;
                Guid g = KernelNetwork;
                rc = EnableTraceEx2(h, ref g, 1, 5, 0x30, 0, 0, IntPtr.Zero);
                if (rc != 0) { StopSession(); return "EnableTraceEx2 xato kodi " + rc; }
            }
            finally { Marshal.FreeHGlobal(props); }

            callback = new EventRecordCallbackFn(OnEvent);
            if (loggerNamePtr == IntPtr.Zero) loggerNamePtr = Marshal.StringToHGlobalUni(SessionName);
            EVENT_TRACE_LOGFILE lf = new EVENT_TRACE_LOGFILE();
            lf.LoggerName = loggerNamePtr;
            lf.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
            lf.EventRecordCallback = Marshal.GetFunctionPointerForDelegate(callback);
            ulong th = OpenTrace(ref lf);
            if (th == INVALID64 || th == INVALID32)
            {
                int e = Marshal.GetLastWin32Error();
                StopSession();
                return "OpenTrace xato kodi " + e;
            }
            traceHandle = th;
            running = true;
            Thread t = new Thread(Pump);
            t.IsBackground = true;
            t.Start();
            return null;
        }
    }

    static void Pump()
    {
        try { ProcessTrace(new ulong[] { traceHandle }, 1, IntPtr.Zero, IntPtr.Zero); }
        catch { }
        running = false;
    }

    public static void Stop()
    {
        lock (sync)
        {
            StopSession();
            if (traceHandle != 0) { CloseTrace(traceHandle); traceHandle = 0; }
            running = false;
        }
    }

    public static void Reset()
    {
        lock (stats) { stats.Clear(); }
    }

    public static FwNetStat[] Snapshot()
    {
        List<FwNetStat> list = new List<FwNetStat>();
        lock (stats)
        {
            foreach (KeyValuePair<int, long[]> kv in stats)
            {
                FwNetStat s = new FwNetStat();
                s.Pid = kv.Key;
                s.Sent = Interlocked.Read(ref kv.Value[0]);
                s.Recv = Interlocked.Read(ref kv.Value[1]);
                list.Add(s);
            }
        }
        return list.ToArray();
    }

    static bool IsLoopback(IntPtr data, int len, bool v6)
    {
        if (!v6)
        {
            if (len < 16) return false;
            int daddr = Marshal.ReadInt32(data, 8);
            return (daddr & 0xFF) == 127;
        }
        if (len < 24) return false;
        for (int i = 0; i < 15; i++) if (Marshal.ReadByte(data, 8 + i) != 0) return false;
        return Marshal.ReadByte(data, 23) == 1;
    }

    static void OnEvent(IntPtr rec)
    {
        try
        {
            int id = (ushort)Marshal.ReadInt16(rec, 40);
            bool send, v6;
            switch (id)
            {
                case 10: case 26: send = true;  v6 = false; break;
                case 11: case 27: send = false; v6 = false; break;
                case 42: case 58: send = true;  v6 = true;  break;
                case 43: case 59: send = false; v6 = true;  break;
                default: return;
            }
            int len = (ushort)Marshal.ReadInt16(rec, 86);
            if (len < 8) return;
            IntPtr data = Marshal.ReadIntPtr(rec, 88 + IntPtr.Size);
            if (data == IntPtr.Zero) return;
            if (IsLoopback(data, len, v6)) return;
            int pid = Marshal.ReadInt32(data, 0);
            long size = (uint)Marshal.ReadInt32(data, 4);
            Interlocked.Increment(ref events);
            long[] c;
            lock (stats)
            {
                if (!stats.TryGetValue(pid, out c)) { c = new long[2]; stats[pid] = c; }
            }
            Interlocked.Add(ref c[send ? 0 : 1], size);
        }
        catch { }
    }
}
'@
}

# --------------------------------------------------------------
#  Ranglar / shrift
# --------------------------------------------------------------
$clrBg     = [System.Drawing.Color]::FromArgb(30,30,35)
$clrPanel  = [System.Drawing.Color]::FromArgb(45,45,52)
$clrText   = [System.Drawing.Color]::WhiteSmoke
$clrAccent = [System.Drawing.Color]::FromArgb(0,150,220)
$clrGreen  = [System.Drawing.Color]::FromArgb(60,180,90)
$clrRed    = [System.Drawing.Color]::FromArgb(210,70,70)
$fontMain  = New-Object System.Drawing.Font("Segoe UI",9)
$fontBold  = New-Object System.Drawing.Font("Segoe UI",9,[System.Drawing.FontStyle]::Bold)
$fontMono  = New-Object System.Drawing.Font("Consolas",10)

$script:HostsPath = "$env:WinDir\System32\drivers\etc\hosts"
$script:HostsTag  = "#FWDASH"

# --------------------------------------------------------------
#  Asosiy oyna
# --------------------------------------------------------------
$form               = New-Object System.Windows.Forms.Form
$form.Text          = "Windows Firewall Dashboard"
$form.Size          = New-Object System.Drawing.Size(1060,720)
$form.StartPosition = "CenterScreen"
$form.BackColor     = $clrBg
$form.ForeColor     = $clrText
$form.Font          = $fontMain
$form.MinimumSize   = New-Object System.Drawing.Size(920,600)

# ---- Yuqori panel: profillar ----
$topPanel           = New-Object System.Windows.Forms.Panel
$topPanel.Dock      = 'Top'
$topPanel.Height    = 96
$topPanel.BackColor = $clrPanel
$form.Controls.Add($topPanel)

$profileControls = @{}
$profiles = @('Domain','Private','Public')
$x = 12
foreach ($p in $profiles) {
    $box           = New-Object System.Windows.Forms.Panel
    $box.Size      = New-Object System.Drawing.Size(210,72)
    $box.Location  = New-Object System.Drawing.Point($x,12)
    $box.BackColor = $clrBg
    $topPanel.Controls.Add($box)

    $lbl          = New-Object System.Windows.Forms.Label
    $lbl.Text     = "$p profil"; $lbl.Font = $fontBold
    $lbl.Location = New-Object System.Drawing.Point(10,8); $lbl.AutoSize = $true
    $box.Controls.Add($lbl)

    $state          = New-Object System.Windows.Forms.Label
    $state.Location = New-Object System.Drawing.Point(10,32); $state.AutoSize = $true
    $box.Controls.Add($state)

    $btn           = New-Object System.Windows.Forms.Button
    $btn.Size      = New-Object System.Drawing.Size(80,26)
    $btn.Location  = New-Object System.Drawing.Point(118,32)
    $btn.FlatStyle = 'Flat'; $btn.ForeColor = $clrText
    $box.Controls.Add($btn)

    $profileControls[$p] = @{ State = $state; Button = $btn }
    $x += 220
}

$btnMaster           = New-Object System.Windows.Forms.Button
$btnMaster.Text      = "Barchasini boshqarish"
$btnMaster.Size      = New-Object System.Drawing.Size(150,44)
$btnMaster.Location  = New-Object System.Drawing.Point(700,24)
$btnMaster.FlatStyle = 'Flat'; $btnMaster.BackColor = $clrAccent
$btnMaster.ForeColor = $clrText; $btnMaster.Font = $fontBold
$topPanel.Controls.Add($btnMaster)

# ---- Status bar ----
$statusBar           = New-Object System.Windows.Forms.StatusStrip
$statusBar.BackColor = $clrPanel
$statusLbl           = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLbl.ForeColor = $clrText
[void]$statusBar.Items.Add($statusLbl)
$form.Controls.Add($statusBar)

# ---- Tab control ----
$tabs            = New-Object System.Windows.Forms.TabControl
$tabs.Dock       = 'Fill'
$tabs.Font       = $fontMain
$form.Controls.Add($tabs)
$tabs.BringToFront()

function New-Tab($title) {
    $tp = New-Object System.Windows.Forms.TabPage
    $tp.Text = $title; $tp.BackColor = $clrBg; $tp.ForeColor = $clrText
    [void]$tabs.TabPages.Add($tp)
    return $tp
}
$tabRules   = New-Tab "Firewall qoidalari"
$tabSites   = New-Tab "Saytlar"
$tabDevices = New-Tab "Qurilmalar (MAC)"
$tabTraffic = New-Tab "Trafik"
$tabConsole = New-Tab "Buyruq konsoli"

# ==============================================================
#  TAB 1 — Firewall qoidalari
# ==============================================================
$panelTop1           = New-Object System.Windows.Forms.Panel
$panelTop1.Dock      = 'Top'; $panelTop1.Height = 82; $panelTop1.BackColor = $clrBg
$tabRules.Controls.Add($panelTop1)

$lblSearch          = New-Object System.Windows.Forms.Label
$lblSearch.Text     = "Qidiruv:"; $lblSearch.Location = New-Object System.Drawing.Point(12,12); $lblSearch.AutoSize = $true
$panelTop1.Controls.Add($lblSearch)

$txtSearch          = New-Object System.Windows.Forms.TextBox
$txtSearch.Location = New-Object System.Drawing.Point(72,9); $txtSearch.Size = New-Object System.Drawing.Size(240,24)
$txtSearch.BackColor= $clrPanel; $txtSearch.ForeColor = $clrText
$panelTop1.Controls.Add($txtSearch)

$cmbDir             = New-Object System.Windows.Forms.ComboBox
$cmbDir.Location    = New-Object System.Drawing.Point(325,9); $cmbDir.Size = New-Object System.Drawing.Size(120,24)
$cmbDir.DropDownStyle= 'DropDownList'; [void]$cmbDir.Items.AddRange(@('Barchasi','Inbound','Outbound')); $cmbDir.SelectedIndex = 0
$panelTop1.Controls.Add($cmbDir)

$cmbAct             = New-Object System.Windows.Forms.ComboBox
$cmbAct.Location    = New-Object System.Drawing.Point(455,9); $cmbAct.Size = New-Object System.Drawing.Size(120,24)
$cmbAct.DropDownStyle= 'DropDownList'; [void]$cmbAct.Items.AddRange(@('Barchasi','Allow','Block')); $cmbAct.SelectedIndex = 0
$panelTop1.Controls.Add($cmbAct)

$chkEnabledOnly          = New-Object System.Windows.Forms.CheckBox
$chkEnabledOnly.Text     = "Faqat yoqilganlar"; $chkEnabledOnly.Location = New-Object System.Drawing.Point(585,11); $chkEnabledOnly.AutoSize = $true
$panelTop1.Controls.Add($chkEnabledOnly)

function New-ActBtn($text,$px,$color,$w=120) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $text; $b.Size = New-Object System.Drawing.Size($w,32)
    $b.Location = New-Object System.Drawing.Point($px,44); $b.FlatStyle = 'Flat'; $b.ForeColor = $clrText
    if ($color) { $b.BackColor = $color }
    $panelTop1.Controls.Add($b); return $b
}
$btnRefresh = New-ActBtn "Yangilash"          12  $null
$btnNew     = New-ActBtn "Yangi qoida"        140 $clrAccent
$btnEnable  = New-ActBtn "Yoqish"             268 $clrGreen
$btnDisable = New-ActBtn "O'chirish"          396 $null
$btnDelete  = New-ActBtn "Butunlay o'chirish" 524 $clrRed 150

$detailBox            = New-Object System.Windows.Forms.TextBox
$detailBox.Dock       = 'Bottom'; $detailBox.Height = 110
$detailBox.Multiline  = $true; $detailBox.ReadOnly = $true; $detailBox.ScrollBars = 'Vertical'
$detailBox.BackColor  = $clrPanel; $detailBox.ForeColor = $clrText
$detailBox.Font       = New-Object System.Drawing.Font("Consolas",9)
$tabRules.Controls.Add($detailBox)

$grid                       = New-Object System.Windows.Forms.DataGridView
$grid.Dock                  = 'Fill'
$grid.BackgroundColor       = $clrBg
$grid.GridColor             = $clrPanel
$grid.BorderStyle           = 'None'
$grid.ReadOnly              = $true
$grid.AllowUserToAddRows    = $false
$grid.AllowUserToDeleteRows = $false
$grid.SelectionMode         = 'FullRowSelect'
$grid.MultiSelect           = $true
$grid.RowHeadersVisible     = $false
$grid.AutoSizeColumnsMode   = 'Fill'
$grid.EnableHeadersVisualStyles = $false
$grid.ColumnHeadersDefaultCellStyle.BackColor = $clrPanel
$grid.ColumnHeadersDefaultCellStyle.ForeColor = $clrText
$grid.ColumnHeadersDefaultCellStyle.Font      = $fontBold
$tabRules.Controls.Add($grid)
$grid.BringToFront()

$cols = @(
    @{n='Enabled';h='Holat';w=8},@{n='DisplayName';h='Nomi';w=34},
    @{n='Direction';h='Yo`nalish';w=12},@{n='Action';h='Amal';w=10},
    @{n='Profile';h='Profil';w=16},@{n='Group';h='Guruh';w=20}
)
foreach ($c in $cols) {
    $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $col.Name = $c.n; $col.HeaderText = $c.h; $col.FillWeight = $c.w
    [void]$grid.Columns.Add($col)
}
$colName = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
$colName.Name = 'RuleName'; $colName.Visible = $false
[void]$grid.Columns.Add($colName)

# ==============================================================
#  TAB 2 — Saytlar (hosts fayli)
# ==============================================================
$panelTop2           = New-Object System.Windows.Forms.Panel
$panelTop2.Dock      = 'Top'; $panelTop2.Height = 84; $panelTop2.BackColor = $clrBg
$tabSites.Controls.Add($panelTop2)

$lblSite            = New-Object System.Windows.Forms.Label
$lblSite.Text       = "Sayt (domen):"; $lblSite.Location = New-Object System.Drawing.Point(12,12); $lblSite.AutoSize = $true
$panelTop2.Controls.Add($lblSite)

$txtSite            = New-Object System.Windows.Forms.TextBox
$txtSite.Location   = New-Object System.Drawing.Point(110,9); $txtSite.Size = New-Object System.Drawing.Size(320,24)
$txtSite.BackColor  = $clrPanel; $txtSite.ForeColor = $clrText
$panelTop2.Controls.Add($txtSite)

$lblSiteHint          = New-Object System.Windows.Forms.Label
$lblSiteHint.Text     = "masalan: facebook.com  (hosts fayli orqali 0.0.0.0 ga yo'naltiriladi)"
$lblSiteHint.Location = New-Object System.Drawing.Point(12,44); $lblSiteHint.AutoSize = $true
$lblSiteHint.ForeColor= [System.Drawing.Color]::Gray
$panelTop2.Controls.Add($lblSiteHint)

$btnSiteBlock            = New-Object System.Windows.Forms.Button
$btnSiteBlock.Text       = "Bloklash"; $btnSiteBlock.Size = New-Object System.Drawing.Size(110,28)
$btnSiteBlock.Location   = New-Object System.Drawing.Point(445,7); $btnSiteBlock.FlatStyle = 'Flat'
$btnSiteBlock.BackColor  = $clrRed; $btnSiteBlock.ForeColor = $clrText
$panelTop2.Controls.Add($btnSiteBlock)

$btnSiteAllow            = New-Object System.Windows.Forms.Button
$btnSiteAllow.Text       = "Ruxsat berish"; $btnSiteAllow.Size = New-Object System.Drawing.Size(120,28)
$btnSiteAllow.Location   = New-Object System.Drawing.Point(565,7); $btnSiteAllow.FlatStyle = 'Flat'
$btnSiteAllow.BackColor  = $clrGreen; $btnSiteAllow.ForeColor = $clrText
$panelTop2.Controls.Add($btnSiteAllow)

$btnSiteRefresh          = New-Object System.Windows.Forms.Button
$btnSiteRefresh.Text     = "Yangilash"; $btnSiteRefresh.Size = New-Object System.Drawing.Size(100,28)
$btnSiteRefresh.Location = New-Object System.Drawing.Point(695,7); $btnSiteRefresh.FlatStyle = 'Flat'
$btnSiteRefresh.ForeColor= $clrText
$panelTop2.Controls.Add($btnSiteRefresh)

$lblBlocked           = New-Object System.Windows.Forms.Label
$lblBlocked.Text      = "Bloklangan saytlar (birini tanlab 'Ruxsat berish' bosing):"
$lblBlocked.Dock      = 'Top'; $lblBlocked.Height = 24; $lblBlocked.TextAlign = 'MiddleLeft'
$tabSites.Controls.Add($lblBlocked)

$lstSites            = New-Object System.Windows.Forms.ListBox
$lstSites.Dock       = 'Fill'
$lstSites.BackColor  = $clrPanel; $lstSites.ForeColor = $clrText; $lstSites.Font = $fontMono
$tabSites.Controls.Add($lstSites)
$lstSites.BringToFront()

# ==============================================================
#  TAB 3 — Qurilmalar (MAC)
# ==============================================================
$panelTop3           = New-Object System.Windows.Forms.Panel
$panelTop3.Dock      = 'Top'; $panelTop3.Height = 76; $panelTop3.BackColor = $clrBg
$tabDevices.Controls.Add($panelTop3)

$lblMac             = New-Object System.Windows.Forms.Label
$lblMac.Text        = "MAC:"; $lblMac.Location = New-Object System.Drawing.Point(12,12); $lblMac.AutoSize = $true
$panelTop3.Controls.Add($lblMac)

$txtMac             = New-Object System.Windows.Forms.TextBox
$txtMac.Location    = New-Object System.Drawing.Point(55,9); $txtMac.Size = New-Object System.Drawing.Size(230,24)
$txtMac.BackColor   = $clrPanel; $txtMac.ForeColor = $clrText
$panelTop3.Controls.Add($txtMac)

$btnDevBlock            = New-Object System.Windows.Forms.Button
$btnDevBlock.Text       = "Bloklash"; $btnDevBlock.Size = New-Object System.Drawing.Size(150,28)
$btnDevBlock.Location   = New-Object System.Drawing.Point(300,7); $btnDevBlock.FlatStyle = 'Flat'
$btnDevBlock.BackColor  = $clrRed; $btnDevBlock.ForeColor = $clrText
$panelTop3.Controls.Add($btnDevBlock)

$btnDevAllow            = New-Object System.Windows.Forms.Button
$btnDevAllow.Text       = "Blokni olib tashlash"; $btnDevAllow.Size = New-Object System.Drawing.Size(170,28)
$btnDevAllow.Location   = New-Object System.Drawing.Point(460,7); $btnDevAllow.FlatStyle = 'Flat'
$btnDevAllow.BackColor  = $clrGreen; $btnDevAllow.ForeColor = $clrText
$panelTop3.Controls.Add($btnDevAllow)

$btnDevRefresh          = New-Object System.Windows.Forms.Button
$btnDevRefresh.Text     = "Tarmoqni skanlash"; $btnDevRefresh.Size = New-Object System.Drawing.Size(150,28)
$btnDevRefresh.Location = New-Object System.Drawing.Point(640,7); $btnDevRefresh.FlatStyle = 'Flat'
$btnDevRefresh.ForeColor= $clrText
$panelTop3.Controls.Add($btnDevRefresh)

$lblDevHint           = New-Object System.Windows.Forms.Label
$lblDevHint.Text      = "Ro'yxatdan qurilma tanlab 'Bloklash' bosing yoki yuqorida MAC kiriting. (Lokal tarmoq, faol qurilmalar)"
$lblDevHint.Location  = New-Object System.Drawing.Point(12,44); $lblDevHint.AutoSize = $true
$lblDevHint.ForeColor = [System.Drawing.Color]::Gray
$panelTop3.Controls.Add($lblDevHint)

$gridDev                       = New-Object System.Windows.Forms.DataGridView
$gridDev.Dock                  = 'Fill'
$gridDev.BackgroundColor       = $clrBg; $gridDev.GridColor = $clrPanel; $gridDev.BorderStyle = 'None'
$gridDev.ReadOnly              = $true
$gridDev.AllowUserToAddRows    = $false; $gridDev.AllowUserToDeleteRows = $false
$gridDev.SelectionMode         = 'FullRowSelect'; $gridDev.MultiSelect = $true
$gridDev.RowHeadersVisible     = $false; $gridDev.AutoSizeColumnsMode = 'Fill'
$gridDev.EnableHeadersVisualStyles = $false
$gridDev.ColumnHeadersDefaultCellStyle.BackColor = $clrPanel
$gridDev.ColumnHeadersDefaultCellStyle.ForeColor = $clrText
$gridDev.ColumnHeadersDefaultCellStyle.Font = $fontBold
$tabDevices.Controls.Add($gridDev)
$gridDev.BringToFront()
foreach ($c in @(@{n='IP';w=25},@{n='MAC';w=30},@{n='Holat';w=20},@{n='Bloklangan';w=25})) {
    $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $col.Name = $c.n; $col.HeaderText = $c.n; $col.FillWeight = $c.w
    [void]$gridDev.Columns.Add($col)
}

# ==============================================================
#  TAB — Trafik (dastur va xizmatlar bo'yicha)
# ==============================================================
$panelTopTr           = New-Object System.Windows.Forms.Panel
$panelTopTr.Dock      = 'Top'; $panelTopTr.Height = 96; $panelTopTr.BackColor = $clrBg
$tabTraffic.Controls.Add($panelTopTr)

function New-TrBtn($text,$px,$color,$w) {
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $text; $b.Size = New-Object System.Drawing.Size($w,28)
    $b.Location = New-Object System.Drawing.Point($px,7); $b.FlatStyle = 'Flat'; $b.ForeColor = $clrText
    if ($color) { $b.BackColor = $color }
    $panelTopTr.Controls.Add($b); return $b
}
$btnTrToggle  = New-TrBtn "To'xtatish"           12  $clrAccent 110
$btnTrReset   = New-TrBtn "Nollash"              130 $null      90
$btnTrBlock   = New-TrBtn "Internetini bloklash" 228 $clrRed    160
$btnTrUnblock = New-TrBtn "Blokni olib tashlash" 396 $clrGreen  160

$lblTrSort          = New-Object System.Windows.Forms.Label
$lblTrSort.Text     = "Saralash:"; $lblTrSort.Location = New-Object System.Drawing.Point(570,13); $lblTrSort.AutoSize = $true
$panelTopTr.Controls.Add($lblTrSort)

$cmbTrSort             = New-Object System.Windows.Forms.ComboBox
$cmbTrSort.Location    = New-Object System.Drawing.Point(632,9); $cmbTrSort.Size = New-Object System.Drawing.Size(130,24)
$cmbTrSort.DropDownStyle = 'DropDownList'
[void]$cmbTrSort.Items.AddRange(@('Jami trafik','Hozirgi tezlik','Yuklab olish','Yuborish')); $cmbTrSort.SelectedIndex = 0
$panelTopTr.Controls.Add($cmbTrSort)

$chkTrGroup          = New-Object System.Windows.Forms.CheckBox
$chkTrGroup.Text     = "Nom bo'yicha guruhlash"; $chkTrGroup.Checked = $true
$chkTrGroup.Location = New-Object System.Drawing.Point(775,11); $chkTrGroup.AutoSize = $true
$panelTopTr.Controls.Add($chkTrGroup)

$lblTrTotal          = New-Object System.Windows.Forms.Label
$lblTrTotal.Text     = "Ma'lumot yig'ilmoqda..."; $lblTrTotal.Font = $fontBold
$lblTrTotal.Location = New-Object System.Drawing.Point(12,46); $lblTrTotal.AutoSize = $true
$panelTopTr.Controls.Add($lblTrTotal)

$lblTrHint           = New-Object System.Windows.Forms.Label
$lblTrHint.Text      = "Hisob dastur ochilgan paytdan boshlanadi. TCP va UDP (QUIC) sanaladi, loopback (127.0.0.1) sanalmaydi. svchost xizmatlari alohida ko'rsatiladi."
$lblTrHint.Location  = New-Object System.Drawing.Point(12,72); $lblTrHint.AutoSize = $true
$lblTrHint.ForeColor = [System.Drawing.Color]::Gray
$panelTopTr.Controls.Add($lblTrHint)

$gridTr                       = New-Object System.Windows.Forms.DataGridView
$gridTr.Dock                  = 'Fill'
$gridTr.BackgroundColor       = $clrBg; $gridTr.GridColor = $clrPanel; $gridTr.BorderStyle = 'None'
$gridTr.ReadOnly              = $true
$gridTr.AllowUserToAddRows    = $false; $gridTr.AllowUserToDeleteRows = $false
$gridTr.SelectionMode         = 'FullRowSelect'; $gridTr.MultiSelect = $false
$gridTr.RowHeadersVisible     = $false; $gridTr.AutoSizeColumnsMode = 'Fill'
$gridTr.EnableHeadersVisualStyles = $false
$gridTr.ColumnHeadersDefaultCellStyle.BackColor = $clrPanel
$gridTr.ColumnHeadersDefaultCellStyle.ForeColor = $clrText
$gridTr.ColumnHeadersDefaultCellStyle.Font = $fontBold
$tabTraffic.Controls.Add($gridTr)
$gridTr.BringToFront()
foreach ($c in @(
    @{n='Dastur';h='Dastur';w=16},@{n='PID';h='PID';w=9},@{n='Info';h='Xizmat / tavsif';w=27},
    @{n='Down';h='↓ Hozir';w=9},@{n='Up';h='↑ Hozir';w=9},
    @{n='DownTot';h='↓ Jami';w=9},@{n='UpTot';h='↑ Jami';w=9},@{n='Total';h='Jami';w=9},@{n='Holat';h='Holat';w=11})) {
    $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $col.Name = $c.n; $col.HeaderText = $c.h; $col.FillWeight = $c.w; $col.SortMode = 'NotSortable'
    [void]$gridTr.Columns.Add($col)
}
foreach ($hn in @('Key','Path')) {
    $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
    $col.Name = $hn; $col.Visible = $false
    [void]$gridTr.Columns.Add($col)
}

$trTimer          = New-Object System.Windows.Forms.Timer
$trTimer.Interval = 2000

# ==============================================================
#  TAB 4 — Buyruq konsoli
# ==============================================================
$panelBtm4           = New-Object System.Windows.Forms.Panel
$panelBtm4.Dock      = 'Bottom'; $panelBtm4.Height = 44; $panelBtm4.BackColor = $clrPanel
$tabConsole.Controls.Add($panelBtm4)

$inp                = New-Object System.Windows.Forms.TextBox
$inp.Location       = New-Object System.Drawing.Point(10,9); $inp.Size = New-Object System.Drawing.Size(830,26)
$inp.BackColor      = $clrBg; $inp.ForeColor = $clrText; $inp.Font = $fontMono
$panelBtm4.Controls.Add($inp)

$btnRun             = New-Object System.Windows.Forms.Button
$btnRun.Text        = "Ishga tushirish"; $btnRun.Size = New-Object System.Drawing.Size(150,28)
$btnRun.Location    = New-Object System.Drawing.Point(850,8); $btnRun.FlatStyle = 'Flat'
$btnRun.BackColor   = $clrAccent; $btnRun.ForeColor = $clrText; $btnRun.Font = $fontBold
$panelBtm4.Controls.Add($btnRun)

$con                = New-Object System.Windows.Forms.RichTextBox
$con.Dock           = 'Fill'; $con.ReadOnly = $true
$con.BackColor      = [System.Drawing.Color]::FromArgb(20,20,24); $con.ForeColor = [System.Drawing.Color]::LightGreen
$con.Font           = $fontMono
$tabConsole.Controls.Add($con)
$con.BringToFront()

# ==============================================================
#  YORDAMCHI FUNKSIYALAR
# ==============================================================
function Set-Status($m) { $statusLbl.Text = "$(Get-Date -Format 'HH:mm:ss')  —  $m"; $statusBar.Refresh() }

function Write-Console($t) {
    $con.AppendText("$t`r`n")
    $con.SelectionStart = $con.Text.Length
    $con.ScrollToCaret()
}

function Show-Help {
    $h = @"
============================  BUYRUQLAR  ============================
  block site <domen>     saytni bloklash        (m: block site facebook.com)
  allow site <domen>     saytga ruxsat berish
  list sites             bloklangan saytlar ro'yxati

  block mac <MAC>        qurilmani MAC bo'yicha bloklash
  allow mac <MAC>        MAC blokini olib tashlash

  block ip <IP>          IP manzilni bloklash
  allow ip <IP>          IP blokini olib tashlash

  block port <port>      TCP portni bloklash (inbound)
  allow port <port>      port blokini olib tashlash

  block app <nom>        dastur internetini bloklash (m: block app chrome)
  allow app <nom>        dastur blokini olib tashlash
  trafik                 eng ko'p trafik ishlatayotgan dasturlar (top 15)


  firewall on            barcha profillarni YOQISH
  firewall off           barcha profillarni O'CHIRISH
  devices                tarmoqdagi qurilmalarni skanlash
  clear                  konsolni tozalash
  help                   shu yordam

  (Uzbekcha: blok/ruxsat, sayt/site so'zlari ham ishlaydi)
====================================================================
"@
    Write-Console $h
}

function Update-ProfileStatus {
    try {
        $fp = Get-NetFirewallProfile -ErrorAction Stop
        foreach ($p in $profiles) {
            $on  = [bool]($fp | Where-Object Name -eq $p).Enabled
            $ctl = $profileControls[$p]
            if ($on) {
                $ctl.State.Text = "● YOQILGAN"; $ctl.State.ForeColor = $clrGreen
                $ctl.Button.Text = "O'chirish";  $ctl.Button.BackColor = $clrRed
            } else {
                $ctl.State.Text = "● O'CHIRILGAN"; $ctl.State.ForeColor = $clrRed
                $ctl.Button.Text = "Yoqish";       $ctl.Button.BackColor = $clrGreen
            }
        }
    } catch { Set-Status "Profil holati xatosi: $($_.Exception.Message)" }
}

function Load-Rules {
    Set-Status "Qoidalar yuklanmoqda..."
    $grid.Rows.Clear()
    try {
        $rules  = Get-NetFirewallRule -ErrorAction Stop
        $search = $txtSearch.Text.Trim(); $dir = $cmbDir.SelectedItem
        $act    = $cmbAct.SelectedItem;   $onlyOn = $chkEnabledOnly.Checked
        $filtered = $rules | Where-Object {
            ($dir -eq 'Barchasi' -or $_.Direction -eq $dir) -and
            ($act -eq 'Barchasi' -or $_.Action -eq $act) -and
            (-not $onlyOn -or $_.Enabled -eq 'True') -and
            ([string]::IsNullOrEmpty($search) -or $_.DisplayName -like "*$search*" -or $_.Name -like "*$search*")
        }
        foreach ($r in $filtered) {
            $isOn = ($r.Enabled -eq 'True')
            $idx = $grid.Rows.Add($(if($isOn){"✔ Yoq"}else{"✖ O'ch"}),$r.DisplayName,$r.Direction,$r.Action,$r.Profile,$r.DisplayGroup,$r.Name)
            $row = $grid.Rows[$idx]
            if ($r.Action -eq 'Block') { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(255,232,232) }
            else { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(232,245,235) }
            $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Black
            if (-not $isOn) { $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Gray }
        }
        Set-Status "$($grid.Rows.Count) ta qoida (jami $($rules.Count))."
    } catch { Set-Status "Xato: $($_.Exception.Message)" }
}

function Get-SelectedRuleNames { $grid.SelectedRows | ForEach-Object { $_.Cells['RuleName'].Value } }

function Show-RuleDetails($name) {
    try {
        $r  = Get-NetFirewallRule -Name $name -ErrorAction Stop
        $pf = $r | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
        $af = $r | Get-NetFirewallApplicationFilter -ErrorAction SilentlyContinue
        $ad = $r | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue
        $detailBox.Text = @"
Nomi      : $($r.DisplayName)
Ichki ID  : $($r.Name)
Yo'nalish : $($r.Direction)   Amal: $($r.Action)   Yoqilgan: $($r.Enabled)
Protokol  : $($pf.Protocol)   Local: $($pf.LocalPort)   Remote: $($pf.RemotePort)
Dastur    : $($af.Program)
Manzil    : Local $($ad.LocalAddress)   Remote $($ad.RemoteAddress)
"@
    } catch { $detailBox.Text = "Detal o'qilmadi: $($_.Exception.Message)" }
}

function Show-NewRuleDialog {
    $dlg = New-Object System.Windows.Forms.Form
    $dlg.Text = "Yangi firewall qoidasi"; $dlg.Size = New-Object System.Drawing.Size(440,430)
    $dlg.StartPosition = "CenterParent"; $dlg.BackColor = $clrBg; $dlg.ForeColor = $clrText
    $dlg.FormBorderStyle = 'FixedDialog'; $dlg.MaximizeBox = $false
    $script:y = 15
    function Add-L($t){ $l=New-Object System.Windows.Forms.Label; $l.Text=$t; $l.Location=New-Object System.Drawing.Point(15,$script:y); $l.AutoSize=$true; $dlg.Controls.Add($l); $script:y+=22 }
    Add-L "Qoida nomi:"
    $tN=New-Object System.Windows.Forms.TextBox; $tN.Location=New-Object System.Drawing.Point(15,$y); $tN.Size=New-Object System.Drawing.Size(390,24); $tN.BackColor=$clrPanel; $tN.ForeColor=$clrText; $dlg.Controls.Add($tN); $y+=34
    Add-L "Yo'nalish / Amal:"
    $cD=New-Object System.Windows.Forms.ComboBox; $cD.Location=New-Object System.Drawing.Point(15,$y); $cD.Size=New-Object System.Drawing.Size(180,24); $cD.DropDownStyle='DropDownList'; [void]$cD.Items.AddRange(@('Inbound','Outbound')); $cD.SelectedIndex=0; $dlg.Controls.Add($cD)
    $cA=New-Object System.Windows.Forms.ComboBox; $cA.Location=New-Object System.Drawing.Point(225,$y); $cA.Size=New-Object System.Drawing.Size(180,24); $cA.DropDownStyle='DropDownList'; [void]$cA.Items.AddRange(@('Allow','Block')); $cA.SelectedIndex=0; $dlg.Controls.Add($cA); $y+=34
    Add-L "Protokol / Port:"
    $cP=New-Object System.Windows.Forms.ComboBox; $cP.Location=New-Object System.Drawing.Point(15,$y); $cP.Size=New-Object System.Drawing.Size(180,24); $cP.DropDownStyle='DropDownList'; [void]$cP.Items.AddRange(@('Any','TCP','UDP')); $cP.SelectedIndex=0; $dlg.Controls.Add($cP)
    $tPo=New-Object System.Windows.Forms.TextBox; $tPo.Location=New-Object System.Drawing.Point(225,$y); $tPo.Size=New-Object System.Drawing.Size(180,24); $tPo.BackColor=$clrPanel; $tPo.ForeColor=$clrText; $dlg.Controls.Add($tPo); $y+=6
    $lh=New-Object System.Windows.Forms.Label; $lh.Text="masalan: 80  yoki  80,443  yoki  8000-8100"; $lh.Location=New-Object System.Drawing.Point(225,($y+22)); $lh.AutoSize=$true; $lh.ForeColor=[System.Drawing.Color]::Gray; $dlg.Controls.Add($lh); $y+=44
    Add-L "Dastur yo'li (ixtiyoriy):"
    $tPr=New-Object System.Windows.Forms.TextBox; $tPr.Location=New-Object System.Drawing.Point(15,$y); $tPr.Size=New-Object System.Drawing.Size(300,24); $tPr.BackColor=$clrPanel; $tPr.ForeColor=$clrText; $dlg.Controls.Add($tPr)
    $bB=New-Object System.Windows.Forms.Button; $bB.Text="..."; $bB.Location=New-Object System.Drawing.Point(325,$y); $bB.Size=New-Object System.Drawing.Size(80,24); $bB.FlatStyle='Flat'; $bB.ForeColor=$clrText; $dlg.Controls.Add($bB); $y+=34
    $bB.Add_Click({ $o=New-Object System.Windows.Forms.OpenFileDialog; $o.Filter="Dasturlar (*.exe)|*.exe|Barchasi (*.*)|*.*"; if($o.ShowDialog() -eq 'OK'){ $tPr.Text=$o.FileName } })
    Add-L "Profil:"
    $cPf=New-Object System.Windows.Forms.ComboBox; $cPf.Location=New-Object System.Drawing.Point(15,$y); $cPf.Size=New-Object System.Drawing.Size(180,24); $cPf.DropDownStyle='DropDownList'; [void]$cPf.Items.AddRange(@('Any','Domain','Private','Public')); $cPf.SelectedIndex=0; $dlg.Controls.Add($cPf)
    $ck=New-Object System.Windows.Forms.CheckBox; $ck.Text="Darhol yoqilsin"; $ck.Checked=$true; $ck.Location=New-Object System.Drawing.Point(225,($y+2)); $ck.AutoSize=$true; $dlg.Controls.Add($ck); $y+=40
    $ok=New-Object System.Windows.Forms.Button; $ok.Text="Yaratish"; $ok.Size=New-Object System.Drawing.Size(120,34); $ok.Location=New-Object System.Drawing.Point(150,$y); $ok.FlatStyle='Flat'; $ok.BackColor=$clrAccent; $ok.ForeColor=$clrText; $ok.Font=$fontBold; $dlg.Controls.Add($ok)
    $cn=New-Object System.Windows.Forms.Button; $cn.Text="Bekor"; $cn.Size=New-Object System.Drawing.Size(100,34); $cn.Location=New-Object System.Drawing.Point(285,$y); $cn.FlatStyle='Flat'; $cn.ForeColor=$clrText; $cn.DialogResult='Cancel'; $dlg.Controls.Add($cn); $dlg.CancelButton=$cn
    $ok.Add_Click({
        if([string]::IsNullOrWhiteSpace($tN.Text)){ [System.Windows.Forms.MessageBox]::Show("Nom kiriting.","Xato",'OK','Warning'); return }
        $pm=@{ DisplayName=$tN.Text.Trim(); Direction=$cD.SelectedItem; Action=$cA.SelectedItem; Enabled=$(if($ck.Checked){'True'}else{'False'}) }
        if($cP.SelectedItem -ne 'Any'){ $pm['Protocol']=$cP.SelectedItem }
        if(-not [string]::IsNullOrWhiteSpace($tPo.Text)){ $pm['LocalPort']=$tPo.Text.Trim() }
        if(-not [string]::IsNullOrWhiteSpace($tPr.Text)){ $pm['Program']=$tPr.Text.Trim() }
        if($cPf.SelectedItem -ne 'Any'){ $pm['Profile']=$cPf.SelectedItem }
        try { New-NetFirewallRule @pm -ErrorAction Stop | Out-Null; $dlg.DialogResult='OK'; $dlg.Close() }
        catch { [System.Windows.Forms.MessageBox]::Show("Xato:`n$($_.Exception.Message)","Xato",'OK','Error') }
    })
    if($dlg.ShowDialog($form) -eq 'OK'){ Set-Status "Yangi qoida yaratildi."; Load-Rules }
}

# ---- Saytlar (hosts) ----
function Get-BlockedSites {
    if (-not (Test-Path $HostsPath)) { return @() }
    Get-Content $HostsPath | Where-Object { $_ -match [regex]::Escape($HostsTag) } | ForEach-Object {
        $p = ($_ -replace [regex]::Escape($HostsTag),'').Trim() -split '\s+'
        if ($p.Count -ge 2) { $p[1] }
    } | Sort-Object -Unique
}
function Clean-Domain($d) { ($d.Trim().ToLower() -replace '^https?://','' -replace '/.*$','' -replace '^www\.','') }
function Block-Site($d) {
    $d = Clean-Domain $d
    if (-not $d) { return "Domen bo'sh." }
    if ((Get-BlockedSites) -contains $d) { return "$d allaqachon bloklangan." }
    Add-Content -Path $HostsPath -Value @("0.0.0.0 $d $HostsTag","0.0.0.0 www.$d $HostsTag") -Encoding ascii
    ipconfig /flushdns | Out-Null
    return "BLOKLANDI: $d"
}
function Unblock-Site($d) {
    $d = Clean-Domain $d
    if (-not (Test-Path $HostsPath)) { return "hosts topilmadi." }
    $keep = Get-Content $HostsPath | Where-Object { -not ($_ -match [regex]::Escape($HostsTag) -and $_ -match "\b$([regex]::Escape($d))\b") }
    Set-Content -Path $HostsPath -Value $keep -Encoding ascii
    ipconfig /flushdns | Out-Null
    return "RUXSAT BERILDI: $d"
}
function Refresh-Sites { $lstSites.Items.Clear(); foreach ($s in (Get-BlockedSites)) { [void]$lstSites.Items.Add($s) } }

# ---- MAC / IP / Port ----
function MacKey($m) { $x = ($m -replace '[^0-9A-Fa-f]','').ToUpper(); if ($x.Length -ne 12) { return $null }; return $x }
function MacPretty($k) { (0..5 | ForEach-Object { $k.Substring($_*2,2) }) -join '-' }
function Get-Devices {
    Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
        $_.LinkLayerAddress -and (MacKey $_.LinkLayerAddress) -and
        $_.State -in 'Reachable','Stale','Permanent' -and
        $_.IPAddress -notmatch '^(0\.|127\.|224\.|239\.|255\.|.*\.255$)'
    } | Select-Object IPAddress, LinkLayerAddress, State
}
function Get-BlockedMacKeys {
    Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object Name -like 'FWDASH-MAC-*' | ForEach-Object { ($_.Name -split '-')[2] } | Select-Object -Unique
}
function Block-Mac($m) {
    $k = MacKey $m; if (-not $k) { return "MAC format noto'g'ri (m: AA-BB-CC-DD-EE-FF)." }
    $nb = Get-NetNeighbor -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { (MacKey $_.LinkLayerAddress) -eq $k -and $_.State -in 'Reachable','Stale','Permanent' }
    if (-not $nb) { return "MAC $(MacPretty $k) tarmoqda faol emas / keshda yo'q. Qurilma yoniq bo'lsin yoki IP bilan bloklang." }
    $ips = $nb.IPAddress | Select-Object -Unique
    foreach ($ip in $ips) {
        $n = "FWDASH-MAC-$k-$ip"
        Remove-NetFirewallRule -Name $n,"$n-out" -ErrorAction SilentlyContinue
        New-NetFirewallRule -Name $n -DisplayName "FWDASH MAC $(MacPretty $k) ($ip) in" -Direction Inbound -Action Block -RemoteAddress $ip -ErrorAction Stop | Out-Null
        New-NetFirewallRule -Name "$n-out" -DisplayName "FWDASH MAC $(MacPretty $k) ($ip) out" -Direction Outbound -Action Block -RemoteAddress $ip -ErrorAction Stop | Out-Null
    }
    return "BLOKLANDI: MAC $(MacPretty $k) -> IP: $($ips -join ', ')"
}
function Unblock-Mac($m) {
    $k = MacKey $m; if (-not $k) { return "MAC format noto'g'ri." }
    $r = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object Name -like "FWDASH-MAC-$k-*"
    if ($r) { $r | Remove-NetFirewallRule -ErrorAction SilentlyContinue }
    return "RUXSAT BERILDI: MAC $(MacPretty $k) bloki olib tashlandi."
}
function Block-Ip($ip) {
    if ($ip -notmatch '^\d{1,3}(\.\d{1,3}){3}$') { return "IP format noto'g'ri." }
    $n = "FWDASH-IP-$ip"; Remove-NetFirewallRule -Name $n,"$n-out" -ErrorAction SilentlyContinue
    New-NetFirewallRule -Name $n -DisplayName "FWDASH IP $ip in" -Direction Inbound -Action Block -RemoteAddress $ip -ErrorAction Stop | Out-Null
    New-NetFirewallRule -Name "$n-out" -DisplayName "FWDASH IP $ip out" -Direction Outbound -Action Block -RemoteAddress $ip -ErrorAction Stop | Out-Null
    return "BLOKLANDI: IP $ip"
}
function Unblock-Ip($ip) { $n="FWDASH-IP-$ip"; Remove-NetFirewallRule -Name $n,"$n-out" -ErrorAction SilentlyContinue; return "RUXSAT BERILDI: IP $ip" }
function Block-Port($p) {
    if ($p -notmatch '^\d+(-\d+)?$') { return "Port noto'g'ri." }
    $n="FWDASH-PORT-$p"; Remove-NetFirewallRule -Name $n -ErrorAction SilentlyContinue
    New-NetFirewallRule -Name $n -DisplayName "FWDASH Port $p in" -Direction Inbound -Action Block -Protocol TCP -LocalPort $p -ErrorAction Stop | Out-Null
    return "BLOKLANDI: TCP port $p (inbound)"
}
function Unblock-Port($p) { Remove-NetFirewallRule -Name "FWDASH-PORT-$p" -ErrorAction SilentlyContinue; return "RUXSAT BERILDI: port $p" }

function Refresh-Devices {
    Set-Status "Tarmoq skanlanmoqda..."
    $gridDev.Rows.Clear()
    $blocked = @(Get-BlockedMacKeys)
    foreach ($d in (Get-Devices)) {
        $k = MacKey $d.LinkLayerAddress
        $isB = $blocked -contains $k
        $idx = $gridDev.Rows.Add($d.IPAddress, (MacPretty $k), $d.State, $(if($isB){"✖ BLOKLANGAN"}else{"— ochiq"}))
        $row = $gridDev.Rows[$idx]
        $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Black
        if ($isB) { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(255,232,232) }
        else { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::White }
    }
    Set-Status "$($gridDev.Rows.Count) ta qurilma topildi."
}


# ---- Trafik monitoringi ----
$script:TrPrev      = @{}
$script:TrPrevTime  = $null
$script:TrLast      = @()
$script:PidInfo     = @{}
$script:SvcMap      = @{}
$script:SvcMapTime  = $null
$script:BlockedApps = @()

function Format-Bytes([double]$b) {
    if ($b -ge 1GB) { return ('{0:N2} GB' -f ($b / 1GB)) }
    if ($b -ge 1MB) { return ('{0:N1} MB' -f ($b / 1MB)) }
    if ($b -ge 1KB) { return ('{0:N0} KB' -f ($b / 1KB)) }
    return ('{0:N0} B' -f $b)
}
function Format-Rate([double]$b) { if ($b -lt 1) { return '' }; return ((Format-Bytes $b) + '/s') }

function Update-ServiceMap {
    $map = @{}
    Get-CimInstance Win32_Service -Filter "State='Running'" -ErrorAction SilentlyContinue | ForEach-Object {
        $id = [int]$_.ProcessId
        if ($id -gt 0) {
            if (-not $map.ContainsKey($id)) { $map[$id] = New-Object System.Collections.Generic.List[string] }
            $map[$id].Add($_.Name)
        }
    }
    $script:SvcMap = $map
}

function Update-BlockedApps {
    $script:BlockedApps = @(Get-NetFirewallRule -Name 'FWDASH-APP-*' -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -notlike '*-in' } | ForEach-Object { $_.Name.Substring(11) })
}

function Get-PidInfo([int]$id, $procs) {
    $p = $procs[$id]
    $info = $script:PidInfo[$id]
    if ($p -and (-not $info -or $info.Name -ne $p.ProcessName)) {
        $path = ''; $desc = ''
        try { $path = $p.Path } catch {}
        try { $desc = $p.Description } catch {}
        $info = @{ Name = $p.ProcessName; Path = $path; Desc = $desc }
        $script:PidInfo[$id] = $info
    }
    if (-not $info) {
        $n = switch ($id) { 0 { "(noma'lum)" } 4 { 'System' } default { "PID $id (yopilgan)" } }
        $info = @{ Name = $n; Path = ''; Desc = '' }
        $script:PidInfo[$id] = $info
    }
    return $info
}

function Update-Traffic {
    if (-not [FwNetMon]::IsRunning) { $btnTrToggle.Text = "Boshlash"; return }
    $now = [DateTime]::UtcNow
    $dt  = if ($script:TrPrevTime) { ($now - $script:TrPrevTime).TotalSeconds } else { 0 }
    $script:TrPrevTime = $now
    $snap  = [FwNetMon]::Snapshot()
    $procs = @{}; foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) { $procs[$p.Id] = $p }
    if (-not $script:SvcMapTime -or ($now - $script:SvcMapTime).TotalSeconds -gt 20) { Update-ServiceMap; $script:SvcMapTime = $now }

    $group = $chkTrGroup.Checked
    $groups = @{}; $newPrev = @{}
    foreach ($s in $snap) {
        $id = [int]$s.Pid
        $rS = 0.0; $rR = 0.0
        $prev = $script:TrPrev[$id]
        if ($prev -and $dt -gt 0) {
            $rS = [math]::Max(0, $s.Sent - $prev[0]) / $dt
            $rR = [math]::Max(0, $s.Recv - $prev[1]) / $dt
        }
        $newPrev[$id] = @($s.Sent, $s.Recv)
        $info = Get-PidInfo $id $procs
        $key  = if ($group -and $info.Name -ne 'svchost') { $info.Name } else { "$($info.Name)#$id" }
        $g = $groups[$key]
        if (-not $g) {
            $g = [pscustomobject]@{
                Key = $key; Name = $info.Name; Desc = $info.Desc; Path = $info.Path
                Pids = (New-Object System.Collections.Generic.List[int])
                Svcs = (New-Object System.Collections.Generic.List[string])
                Sent = [long]0; Recv = [long]0; RateS = 0.0; RateR = 0.0
            }
            $groups[$key] = $g
        }
        $g.Pids.Add($id)
        if (-not $g.Path -and $info.Path) { $g.Path = $info.Path }
        $sv = $script:SvcMap[$id]
        if ($sv) { foreach ($x in $sv) { if (-not $g.Svcs.Contains($x)) { $g.Svcs.Add($x) } } }
        $g.Sent += $s.Sent; $g.Recv += $s.Recv; $g.RateS += $rS; $g.RateR += $rR
    }
    $script:TrPrev = $newPrev

    $script:TrLast = Sort-Traffic @($groups.Values)
    if ($tabs.SelectedTab -eq $tabTraffic) { Render-Traffic }
}

function Sort-Traffic($items) {
    $sortBy = switch ($cmbTrSort.SelectedIndex) {
        1       { { $_.RateS + $_.RateR } }
        2       { 'Recv' }
        3       { 'Sent' }
        default { { $_.Sent + $_.Recv } }
    }
    return ,@($items | Sort-Object -Property $sortBy -Descending)
}

function Render-Traffic {
    $selKey = $null
    if ($gridTr.SelectedRows.Count -gt 0) { $selKey = $gridTr.SelectedRows[0].Cells['Key'].Value }
    $first = $gridTr.FirstDisplayedScrollingRowIndex
    $gridTr.SuspendLayout()
    $gridTr.Rows.Clear()
    $tS = 0.0; $tR = 0.0; $aS = [long]0; $aR = [long]0
    foreach ($g in $script:TrLast) {
        $tS += $g.RateS; $tR += $g.RateR; $aS += $g.Sent; $aR += $g.Recv
        $info = if ($g.Svcs.Count -gt 0) { $g.Svcs -join ', ' } else { $g.Desc }
        $pids = if ($g.Pids.Count -gt 3) { "$($g.Pids[0]), $($g.Pids[1]), $($g.Pids[2]) +$($g.Pids.Count - 3)" } else { $g.Pids -join ', ' }
        $isB  = $script:BlockedApps -contains $g.Name
        $idx  = $gridTr.Rows.Add($g.Name, $pids, $info,
                    (Format-Rate $g.RateR), (Format-Rate $g.RateS),
                    (Format-Bytes $g.Recv), (Format-Bytes $g.Sent), (Format-Bytes ($g.Sent + $g.Recv)),
                    $(if ($isB) { "✖ BLOKLANGAN" } else { '' }), $g.Key, $g.Path)
        $row = $gridTr.Rows[$idx]
        $row.DefaultCellStyle.ForeColor = [System.Drawing.Color]::Black
        if ($isB) { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(255,232,232) }
        elseif (($g.RateS + $g.RateR) -ge 1MB) { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::FromArgb(255,240,210) }
        else { $row.DefaultCellStyle.BackColor = [System.Drawing.Color]::White }
    }
    $gridTr.ClearSelection()
    if ($selKey) { foreach ($r in $gridTr.Rows) { if ($r.Cells['Key'].Value -eq $selKey) { $r.Selected = $true; break } } }
    if ($first -ge 0 -and $first -lt $gridTr.Rows.Count) { try { $gridTr.FirstDisplayedScrollingRowIndex = $first } catch {} }
    $gridTr.ResumeLayout()
    $state = if ([FwNetMon]::IsRunning) { '' } else { '   [TO''XTATILGAN]' }
    $lblTrTotal.Text = "Hozir:  ↓ $(Format-Bytes $tR)/s   ↑ $(Format-Bytes $tS)/s        Jami:  ↓ $(Format-Bytes $aR)   ↑ $(Format-Bytes $aS)        $($script:TrLast.Count) ta dastur/xizmat$state"
}

function Start-TrafficMonitor {
    $err = [FwNetMon]::Start()
    if ($err) { Set-Status "Trafik monitoringi ishga tushmadi: $err"; $btnTrToggle.Text = "Boshlash"; return }
    $script:TrPrevTime = $null
    $trTimer.Start(); $btnTrToggle.Text = "To'xtatish"
    Set-Status "Trafik monitoringi ishlayapti."
}

function Block-App($name, $path) {
    $name = ($name -replace '\.exe$','').Trim()
    if (-not $path) {
        $p = Get-Process -Name $name -ErrorAction SilentlyContinue | Where-Object { $_.Path } | Select-Object -First 1
        if ($p) { $path = $p.Path; $name = $p.ProcessName }
    }
    if (-not $path) { return "Dastur yo'li topilmadi: $name (dastur ishlab turgan bo'lishi kerak)." }
    if ($path -like "$env:WinDir\*") { return "Windows tizim dasturini bloklash xavfli, bekor qilindi: $path" }
    $n = "FWDASH-APP-$name"
    Remove-NetFirewallRule -Name $n,"$n-in" -ErrorAction SilentlyContinue
    New-NetFirewallRule -Name $n     -DisplayName "FWDASH App $name out" -Direction Outbound -Action Block -Program $path -ErrorAction Stop | Out-Null
    New-NetFirewallRule -Name "$n-in" -DisplayName "FWDASH App $name in" -Direction Inbound  -Action Block -Program $path -ErrorAction Stop | Out-Null
    return "BLOKLANDI: $name ($path)"
}
function Unblock-App($name) {
    $name = ($name -replace '\.exe$','').Trim()
    Remove-NetFirewallRule -Name "FWDASH-APP-$name","FWDASH-APP-$name-in" -ErrorAction SilentlyContinue
    return "RUXSAT BERILDI: $name"
}

# ---- Buyruq interpretatori ----
function Run-Command($raw) {
    $line = $raw.Trim(); if (-not $line) { return }
    Write-Console "> $line"
    $t = $line -split '\s+'
    $a = $t[0].ToLower()
    $o = if ($t.Count -ge 2) { $t[1].ToLower() } else { '' }
    $arg = if ($t.Count -ge 3) { ($t[2..($t.Count-1)] -join ' ') } else { '' }
    $isBlock = $a -in @('block','blok','bloklash')
    $isAllow = $a -in @('allow','unblock','ruxsat','ochish','och')
    try {
        if ($a -in @('help','yordam','?')) { Show-Help; return }
        if ($a -eq 'clear') { $con.Clear(); return }
        if ($a -in @('firewall','fw')) {
            if ($o -in @('on','yoq','yoqish'))  { Set-NetFirewallProfile -Name Domain,Private,Public -Enabled True;  Write-Console "Firewall YOQILDI."; Update-ProfileStatus; return }
            if ($o -in @('off','ochir','ochirish')) { Set-NetFirewallProfile -Name Domain,Private,Public -Enabled False; Write-Console "Firewall O'CHIRILDI."; Update-ProfileStatus; return }
            Write-Console "Foydalanish: firewall on | firewall off"; return
        }
        if ($a -in @('devices','qurilmalar')) { Refresh-Devices; Write-Console "Qurilmalar 'Qurilmalar' tabida yangilandi."; return }
        if ($a -in @('list','royxat') -and ($o -in @('site','sites','sayt','saytlar'))) { Write-Console ("Bloklangan saytlar:`n  " + ((Get-BlockedSites) -join "`n  ")); return }
        if ($a -in @('traffic','trafik','top')) {
            if ($script:TrLast.Count -eq 0) { Write-Console "Hali ma'lumot yo'q (monitoring ishlayaptimi?)."; return }
            Write-Console ("{0,-34} {1,12} {2,12} {3,12}" -f 'Dastur', 'Yuklash', 'Yuborish', 'Jami')
            foreach ($g in ($script:TrLast | Select-Object -First 15)) {
                $nm = if ($g.Svcs.Count -gt 0) { "$($g.Name): $($g.Svcs -join ',')" } else { $g.Name }
                if ($nm.Length -gt 34) { $nm = $nm.Substring(0,33) + '…' }
                Write-Console ("{0,-34} {1,12} {2,12} {3,12}" -f $nm, (Format-Rate $g.RateR), (Format-Rate $g.RateS), (Format-Bytes ($g.Sent + $g.Recv)))
            }
            return
        }
        if ($a -eq 'saytlar') { Write-Console ("Bloklangan saytlar:`n  " + ((Get-BlockedSites) -join "`n  ")); return }

        if ($isBlock -or $isAllow) {
            switch -Regex ($o) {
                '^(site|sayt)$' { if ($isBlock) { Write-Console (Block-Site $arg) } else { Write-Console (Unblock-Site $arg) }; Refresh-Sites; return }
                '^mac$'         { if ($isBlock) { Write-Console (Block-Mac $arg) } else { Write-Console (Unblock-Mac $arg) }; Refresh-Devices; return }
                '^ip$'          { if ($isBlock) { Write-Console (Block-Ip $arg) } else { Write-Console (Unblock-Ip $arg) }; return }
                '^(app|dastur)$' { if ($isBlock) { Write-Console (Block-App $arg $null) } else { Write-Console (Unblock-App $arg) }; Update-BlockedApps; Render-Traffic; return }
                '^port$'        { if ($isBlock) { Write-Console (Block-Port $arg) } else { Write-Console (Unblock-Port $arg) }; return }
                default         { Write-Console "Noma'lum obyekt: '$o'. 'help' yozing."; return }
            }
        }
        Write-Console "Noma'lum buyruq: '$line'. 'help' yozing."
    } catch { Write-Console "XATO: $($_.Exception.Message)" }
}

# ==============================================================
#  HODISALAR
# ==============================================================
foreach ($p in $profiles) {
    $prof = $p
    $profileControls[$p].Button.Add_Click({
        $cur = (Get-NetFirewallProfile -Name $prof).Enabled
        $new = if ($cur) { 'False' } else { 'True' }
        try { Set-NetFirewallProfile -Name $prof -Enabled $new -ErrorAction Stop; Set-Status "$prof -> $new" } catch { Set-Status "Xato: $($_.Exception.Message)" }
        Update-ProfileStatus
    }.GetNewClosure())
}
$btnMaster.Add_Click({
    $anyOn = (Get-NetFirewallProfile | Where-Object Enabled -eq $true).Count -gt 0
    $target = if ($anyOn) { 'False' } else { 'True' }
    $verb = if ($anyOn) { "o'chirmoqchimisiz" } else { "yoqmoqchimisiz" }
    if ([System.Windows.Forms.MessageBox]::Show("Barcha profillar firewall'ini $verb?","Tasdiq",'YesNo','Question') -eq 'Yes') {
        try { Set-NetFirewallProfile -Name Domain,Private,Public -Enabled $target } catch { Set-Status "Xato: $($_.Exception.Message)" }
        Update-ProfileStatus
    }
})
$txtSearch.Add_TextChanged({ Load-Rules })
$cmbDir.Add_SelectedIndexChanged({ Load-Rules })
$cmbAct.Add_SelectedIndexChanged({ Load-Rules })
$chkEnabledOnly.Add_CheckedChanged({ Load-Rules })
$grid.Add_SelectionChanged({ if ($grid.SelectedRows.Count -eq 1) { $n = $grid.SelectedRows[0].Cells['RuleName'].Value; if ($n) { Show-RuleDetails $n } } })
$btnRefresh.Add_Click({ Update-ProfileStatus; Load-Rules })
$btnNew.Add_Click({ Show-NewRuleDialog })
$btnEnable.Add_Click({ $ns=@(Get-SelectedRuleNames); if(-not $ns){Set-Status "Qoida tanlang.";return}; $ns|%{Enable-NetFirewallRule -Name $_ -EA SilentlyContinue}; Set-Status "$($ns.Count) yoqildi."; Load-Rules })
$btnDisable.Add_Click({ $ns=@(Get-SelectedRuleNames); if(-not $ns){Set-Status "Qoida tanlang.";return}; $ns|%{Disable-NetFirewallRule -Name $_ -EA SilentlyContinue}; Set-Status "$($ns.Count) o'chirildi."; Load-Rules })
$btnDelete.Add_Click({
    $ns=@(Get-SelectedRuleNames); if(-not $ns){Set-Status "Qoida tanlang.";return}
    if([System.Windows.Forms.MessageBox]::Show("$($ns.Count) ta qoida BUTUNLAY o'chiriladi. Davom etamizmi?","Tasdiq",'YesNo','Warning') -eq 'Yes'){
        $ns|%{Remove-NetFirewallRule -Name $_ -EA SilentlyContinue}; Set-Status "$($ns.Count) o'chirildi."; Load-Rules }
})

# Saytlar tabi
$btnSiteBlock.Add_Click({ if($txtSite.Text.Trim()){ Set-Status (Block-Site $txtSite.Text); Refresh-Sites; $txtSite.Clear() } })
$btnSiteAllow.Add_Click({
    $d = if($lstSites.SelectedItem){ $lstSites.SelectedItem } else { $txtSite.Text }
    if($d){ Set-Status (Unblock-Site $d); Refresh-Sites; $txtSite.Clear() }
})
$btnSiteRefresh.Add_Click({ Refresh-Sites })
$txtSite.Add_KeyDown({ if($_.KeyCode -eq 'Enter'){ $_.SuppressKeyPress=$true; if($txtSite.Text.Trim()){ Set-Status (Block-Site $txtSite.Text); Refresh-Sites; $txtSite.Clear() } } })

# Qurilmalar tabi
$btnDevRefresh.Add_Click({ Refresh-Devices })
$btnDevBlock.Add_Click({
    if($txtMac.Text.Trim()){ Set-Status (Block-Mac $txtMac.Text); $txtMac.Clear(); Refresh-Devices; return }
    if($gridDev.SelectedRows.Count -eq 0){ Set-Status "Qurilma yoki MAC tanlang."; return }
    foreach($r in $gridDev.SelectedRows){ Set-Status (Block-Mac $r.Cells['MAC'].Value) }
    Refresh-Devices
})
$btnDevAllow.Add_Click({
    if($txtMac.Text.Trim()){ Set-Status (Unblock-Mac $txtMac.Text); $txtMac.Clear(); Refresh-Devices; return }
    if($gridDev.SelectedRows.Count -eq 0){ Set-Status "Qurilma yoki MAC tanlang."; return }
    foreach($r in $gridDev.SelectedRows){ Set-Status (Unblock-Mac $r.Cells['MAC'].Value) }
    Refresh-Devices
})

# Trafik tabi
$trTimer.Add_Tick({ try { Update-Traffic } catch { Set-Status "Trafik xatosi: $($_.Exception.Message)" } })
$btnTrToggle.Add_Click({
    if ([FwNetMon]::IsRunning) {
        [FwNetMon]::Stop(); $trTimer.Stop(); $btnTrToggle.Text = "Boshlash"
        Set-Status "Trafik monitoringi to'xtatildi."; Render-Traffic
    } else { Start-TrafficMonitor }
})
$btnTrReset.Add_Click({
    [FwNetMon]::Reset(); $script:TrPrev = @{}; $script:TrPrevTime = $null; $script:TrLast = @()
    Render-Traffic; Set-Status "Trafik hisoblagichlari nollandi."
})
$btnTrBlock.Add_Click({
    if ($gridTr.SelectedRows.Count -eq 0) { Set-Status "Ro'yxatdan dastur tanlang."; return }
    $r = $gridTr.SelectedRows[0]; $name = [string]$r.Cells['Dastur'].Value; $path = [string]$r.Cells['Path'].Value
    if ([System.Windows.Forms.MessageBox]::Show("'$name' dasturining internetini bloklaymizmi?`n$path","Tasdiq",'YesNo','Question') -ne 'Yes') { return }
    try { Set-Status (Block-App $name $path) } catch { Set-Status "Xato: $($_.Exception.Message)" }
    Update-BlockedApps; Render-Traffic
})
$btnTrUnblock.Add_Click({
    if ($gridTr.SelectedRows.Count -eq 0) { Set-Status "Ro'yxatdan dastur tanlang."; return }
    Set-Status (Unblock-App ([string]$gridTr.SelectedRows[0].Cells['Dastur'].Value))
    Update-BlockedApps; Render-Traffic
})
$cmbTrSort.Add_SelectedIndexChanged({ $script:TrLast = Sort-Traffic $script:TrLast; Render-Traffic })
$chkTrGroup.Add_CheckedChanged({ Set-Status "Guruhlash keyingi yangilanishda (2 soniya) qo'llanadi." })
$tabs.Add_SelectedIndexChanged({ if ($tabs.SelectedTab -eq $tabTraffic) { Render-Traffic } })
$form.Add_FormClosing({ $trTimer.Stop(); try { [FwNetMon]::Stop() } catch {} })

# Konsol tabi
$btnRun.Add_Click({ Run-Command $inp.Text; $inp.Clear() })
$inp.Add_KeyDown({ if($_.KeyCode -eq 'Enter'){ $_.SuppressKeyPress=$true; Run-Command $inp.Text; $inp.Clear() } })

# ==============================================================
#  START
# ==============================================================
$form.Add_Shown({
    Update-ProfileStatus
    Load-Rules
    Refresh-Sites
    Refresh-Devices
    Update-BlockedApps
    Start-TrafficMonitor
    Show-Help
    $form.Activate()
})
[void]$form.ShowDialog()
