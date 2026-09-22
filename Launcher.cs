using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Security.Principal;
using System.Text;
using System.Windows.Forms;

[assembly: AssemblyTitle("Windows Firewall Dashboard")]
[assembly: AssemblyProduct("Windows Firewall Dashboard")]
[assembly: AssemblyVersion("1.0.0.0")]
[assembly: AssemblyFileVersion("1.0.0.0")]

static class Program
{
    [STAThread]
    static int Main(string[] args)
    {
        // 1) Administrator emasmi? -> o'zini RunAs bilan qayta ishga tushiramiz (UAC oynasi)
        if (!IsAdmin())
        {
            try
            {
                var psi = new ProcessStartInfo(Assembly.GetExecutingAssembly().Location);
                psi.UseShellExecute = true;
                psi.Verb = "runas";
                Process.Start(psi);
            }
            catch
            {
                MessageBox.Show("Administrator huquqi kerak.", "Ruxsat yo'q",
                    MessageBoxButtons.OK, MessageBoxIcon.Warning);
            }
            return 0;
        }

        // 2) Ichiga joylangan skriptni vaqtinchalik faylga chiqaramiz (UTF-8 BOM bilan)
        string script;
        using (var s = Assembly.GetExecutingAssembly().GetManifestResourceStream("FirewallDashboard.ps1"))
        using (var r = new StreamReader(s, Encoding.UTF8))
            script = r.ReadToEnd();

        string dir = Path.Combine(Path.GetTempPath(), "FWDash");
        Directory.CreateDirectory(dir);
        string ps1 = Path.Combine(dir, "FirewallDashboard_" + Guid.NewGuid().ToString("N") + ".ps1");
        File.WriteAllText(ps1, script, new UTF8Encoding(true));

        // 3) Windows PowerShell 5.1 ni konsol oynasisiz ishga tushiramiz
        string psExe = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System),
                                    @"WindowsPowerShell\v1.0\powershell.exe");
        if (!File.Exists(psExe)) psExe = "powershell.exe";

        try
        {
            var psi = new ProcessStartInfo(psExe,
                "-NoProfile -NoLogo -ExecutionPolicy Bypass -STA -WindowStyle Hidden -File \"" + ps1 + "\"");
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            using (var p = Process.Start(psi)) { p.WaitForExit(); }
        }
        catch (Exception ex)
        {
            MessageBox.Show("PowerShell ishga tushmadi:\n" + ex.Message, "Xato",
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            try { File.Delete(ps1); } catch { }
        }
        return 0;
    }

    static bool IsAdmin()
    {
        var p = new WindowsPrincipal(WindowsIdentity.GetCurrent());
        return p.IsInRole(WindowsBuiltInRole.Administrator);
    }
}
