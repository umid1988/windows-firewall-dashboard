# 🛡️ Windows Firewall Dashboard

![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1-5391FE)
![License](https://img.shields.io/badge/license-MIT-green)

**🇬🇧 [English](#-english)** · **🇺🇿 [O'zbekcha](#-ozbekcha)**

---

## 🇬🇧 English

A single-file GUI dashboard for Windows Defender Firewall. It is written in PowerShell with Windows Forms. From one window you can control firewall profiles, rules, websites, LAN devices, and per-app network traffic. It also has a simple command console.

### ✨ Features

| Tab | What it does |
|---|---|
| **Firewall rules** | View, search, and filter all rules by direction, action, or state. Create, enable, disable, or delete rules. Shows port, program, and address details for the selected rule. |
| **Websites** | Blocks and unblocks domains through the `hosts` file by redirecting them to `0.0.0.0`. Entries are tagged `#FWDASH`, and the DNS cache is flushed automatically. |
| **Devices (MAC)** | Scans the ARP/neighbor cache for active LAN devices. Blocks a device by MAC by resolving it to its IP and adding inbound and outbound firewall rules. |
| **Traffic** | Shows live bandwidth per app and per service, both current speed and totals. Counts TCP and UDP/QUIC. Lists `svchost` services individually. You can block an app's internet access with one click. |
| **Command console** | Plain-text commands such as `block site facebook.com` or `trafik`. English and Uzbek keywords both work. |

The top panel shows the Domain, Private, and Public profiles, with on/off toggles for each profile and for all of them at once.

### 📋 Requirements

- Windows 10 or 11
- Windows PowerShell 5.1 (built in)
- .NET Framework 4.x (built in)
- Administrator rights. The app asks for elevation (UAC) automatically.

### 🚀 Usage

**Option 1: the EXE.** Download `FirewallDashboard.exe` from [Releases](../../releases) and double-click it.

> The EXE is not code-signed, so SmartScreen may show *"Windows protected your PC"*. Click **More info → Run anyway**. Some antivirus products flag PowerShell launcher EXEs as a false positive. The full source is in this repo, so you can review it or build the EXE yourself.

**Option 2: the script.**

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\FirewallDashboard.ps1
```

### ⌨️ Console commands

| Command | Description |
|---|---|
| `block site <domain>` / `allow site <domain>` | Block or unblock a website |
| `list sites` | List blocked websites |
| `block mac <MAC>` / `allow mac <MAC>` | Block or unblock a LAN device by MAC |
| `block ip <IP>` / `allow ip <IP>` | Block or unblock an IP address (inbound and outbound) |
| `block port <port>` / `allow port <port>` | Block or unblock an inbound TCP port or range (e.g. `8000-8100`) |
| `block app <name>` / `allow app <name>` | Block or unblock an app's network access (e.g. `block app chrome`) |
| `trafik` | Top 15 apps and services by traffic |
| `firewall on` / `firewall off` | Enable or disable all profiles |
| `devices` | Rescan LAN devices |
| `clear` · `help` | Clear the console · Show help |

Uzbek aliases also work: `blok`, `ruxsat`, `sayt`, `dastur`, `qurilmalar`, `yordam`.

### ⚙️ How it works

- **Firewall management** uses the built-in `NetSecurity` cmdlets (`Get/New/Set/Remove-NetFirewallRule`, `Set-NetFirewallProfile`).
- **Rule naming.** Every rule the dashboard creates is prefixed with `FWDASH-`. To find or clean them up, search for `FWDASH` in the Rules tab.
- **MAC blocking.** Windows Firewall cannot filter by MAC address. The MAC is resolved to its current IP through `Get-NetNeighbor`, and that IP is blocked. This only works for devices that are active on the local network, and only on this PC. To cut a device off from the whole network, use your router.
- **Traffic monitoring.** The dashboard starts a real-time ETW session (`FWDash-NetMon`) on the `Microsoft-Windows-Kernel-Network` provider, which is the same data source Resource Monitor uses. It sums bytes from the TCP/UDP send and receive events (IPv4 and IPv6) per process ID. Loopback traffic is ignored. Counting starts when the app opens, and the session stops when the app closes.
- **EXE launcher.** `Launcher.cs` is a small C# wrapper with the script embedded as a resource. It elevates, extracts the script to `%TEMP%` (UTF-8 with BOM), runs it in a hidden PowerShell window, and deletes the temp file on exit.

### 🔨 Building the EXE

**With the included launcher.** No extra tools are needed; `csc.exe` ships with .NET Framework:

```powershell
& "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" `
  /target:winexe /optimize+ /r:System.Windows.Forms.dll `
  /resource:FirewallDashboard.ps1,FirewallDashboard.ps1 `
  /out:FirewallDashboard.exe Launcher.cs
```

**Or with [ps2exe](https://github.com/MScholtes/PS2EXE):**

```powershell
Install-Module ps2exe -Scope CurrentUser
Invoke-ps2exe .\FirewallDashboard.ps1 .\FirewallDashboard.exe -noConsole -requireAdmin
```

### ⚠️ Limitations

- Traffic statistics are not persisted. For 30-day history, see *Settings → Network & internet → Data usage*.
- LAN traffic, such as file copies to a NAS, is counted as well.
- Blocking apps inside `C:\Windows` is deliberately refused, because it can break the system.
- Some browsers use DNS-over-HTTPS, which can bypass `hosts`-file blocking. In that case, disable secure DNS in the browser or also block by IP.

### ⚖️ Disclaimer

This tool is intended for use on computers and networks you own or are authorized to administer. Turning the firewall off or deleting rules lowers your system's protection, so use it carefully.

---

## 🇺🇿 O'zbekcha

Windows Defender Firewall uchun bitta fayldan iborat grafik boshqaruv paneli. U PowerShell va Windows Forms'da yozilgan. Bitta oynadan firewall profillari, qoidalar, saytlar, lokal tarmoqdagi qurilmalar va har bir dasturning internet trafigini boshqarish mumkin. Oddiy buyruq konsoli ham bor.

### ✨ Imkoniyatlar

| Tab | Vazifasi |
|---|---|
| **Firewall qoidalari** | Barcha qoidalarni ko'rish, qidirish, yo'nalish, amal yoki holat bo'yicha filtrlash. Qoida yaratish, yoqish, o'chirish yoki butunlay o'chirish. Tanlangan qoidaning port, dastur va manzil tafsilotlarini ko'rsatadi. |
| **Saytlar** | Domenlarni `hosts` fayli orqali `0.0.0.0` ga yo'naltirib bloklaydi va ruxsat beradi. Yozuvlar `#FWDASH` bilan belgilanadi, DNS keshi avtomatik tozalanadi. |
| **Qurilmalar (MAC)** | ARP/neighbor keshidan tarmoqdagi faol qurilmalarni topadi. Qurilmani MAC bo'yicha bloklaydi: MAC IP'ga o'giriladi va kiruvchi hamda chiquvchi firewall qoidalari qo'shiladi. |
| **Trafik** | Har bir dastur va xizmatning trafigini jonli ko'rsatadi: hozirgi tezlik va jami hajm. TCP va UDP/QUIC sanaladi. `svchost` xizmatlari alohida ko'rinadi. Dasturning internetini bir tugma bilan bloklash mumkin. |
| **Buyruq konsoli** | Oddiy matnli buyruqlar, masalan `block site facebook.com` yoki `trafik`. Inglizcha va o'zbekcha so'zlar ishlaydi. |

Yuqori panelda Domain, Private va Public profillari ko'rinadi. Har birini alohida yoki hammasini birdan yoqib-o'chirish mumkin.

### 📋 Talablar

- Windows 10 yoki 11
- Windows PowerShell 5.1 (o'rnatilgan)
- .NET Framework 4.x (o'rnatilgan)
- Administrator huquqi. Dastur UAC orqali o'zi so'raydi.

### 🚀 Ishga tushirish

**1-usul: EXE.** [Releases](../../releases) bo'limidan `FirewallDashboard.exe` ni yuklab oling va ikki marta bosing.

> EXE raqamli imzoga ega emas, shuning uchun SmartScreen *"Windows protected your PC"* oynasini chiqarishi mumkin. **More info → Run anyway** ni bosing. Ba'zi antiviruslar PowerShell ishga tushiruvchi EXE'larni xato ravishda shubhali deb belgilaydi. To'liq manba kodi shu repoda, uni tekshirishingiz yoki EXE'ni o'zingiz yig'ishingiz mumkin.

**2-usul: skript.**

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\FirewallDashboard.ps1
```

### ⌨️ Konsol buyruqlari

| Buyruq | Tavsif |
|---|---|
| `block site <domen>` / `allow site <domen>` | Saytni bloklash yoki ruxsat berish |
| `list sites` | Bloklangan saytlar ro'yxati |
| `block mac <MAC>` / `allow mac <MAC>` | Qurilmani MAC bo'yicha bloklash yoki blokni olib tashlash |
| `block ip <IP>` / `allow ip <IP>` | IP manzilni bloklash yoki blokni olib tashlash (kiruvchi va chiquvchi) |
| `block port <port>` / `allow port <port>` | Kiruvchi TCP port yoki oraliqni bloklash yoki ochish (m: `8000-8100`) |
| `block app <nom>` / `allow app <nom>` | Dastur internetini bloklash yoki blokni olib tashlash (m: `block app chrome`) |
| `trafik` | Eng ko'p trafik ishlatayotgan 15 ta dastur va xizmat |
| `firewall on` / `firewall off` | Barcha profillarni yoqish yoki o'chirish |
| `devices` | Tarmoqdagi qurilmalarni qayta skanlash |
| `clear` · `help` | Konsolni tozalash · Yordam |

O'zbekcha sinonimlar ham ishlaydi: `blok`, `ruxsat`, `sayt`, `dastur`, `qurilmalar`, `yordam`.

### ⚙️ Qanday ishlaydi

- **Firewall boshqaruvi** Windows'ning o'rnatilgan `NetSecurity` cmdlet'lari orqali ishlaydi (`Get/New/Set/Remove-NetFirewallRule`, `Set-NetFirewallProfile`).
- **Qoidalar nomi.** Dashboard yaratgan barcha qoidalar `FWDASH-` bilan boshlanadi. Ularni topish yoki tozalash uchun Qoidalar tabida `FWDASH` deb qidiring.
- **MAC bloklash.** Windows Firewall MAC manzil bo'yicha filtrlay olmaydi. Shuning uchun MAC `Get-NetNeighbor` orqali joriy IP'ga o'giriladi va o'sha IP bloklanadi. Bu faqat lokal tarmoqdagi faol qurilmalar uchun va faqat shu kompyuterda ishlaydi. Qurilmani butun tarmoqdan uzish uchun routerdan foydalaning.
- **Trafik monitoringi.** `Microsoft-Windows-Kernel-Network` provayderida real vaqtli ETW sessiyasi (`FWDash-NetMon`) ochiladi. Resource Monitor ham xuddi shu manbadan foydalanadi. TCP/UDP yuborish va qabul qilish hodisalaridagi (IPv4 va IPv6) baytlar jarayon ID bo'yicha jamlanadi. Loopback trafigi sanalmaydi. Hisob dastur ochilganda boshlanadi, dastur yopilganda sessiya to'xtatiladi.
- **EXE launcher.** `Launcher.cs` ichiga skript resurs sifatida joylangan kichik C# dastur. U administrator huquqini so'raydi, skriptni `%TEMP%` ga (UTF-8 BOM bilan) chiqaradi, PowerShell'da yashirin oynada ishga tushiradi va yopilganda vaqtinchalik faylni o'chiradi.

### 🔨 EXE yig'ish

**Repodagi launcher bilan.** Qo'shimcha dastur kerak emas, `csc.exe` .NET Framework bilan birga keladi:

```powershell
& "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe" `
  /target:winexe /optimize+ /r:System.Windows.Forms.dll `
  /resource:FirewallDashboard.ps1,FirewallDashboard.ps1 `
  /out:FirewallDashboard.exe Launcher.cs
```

**Yoki [ps2exe](https://github.com/MScholtes/PS2EXE) bilan:**

```powershell
Install-Module ps2exe -Scope CurrentUser
Invoke-ps2exe .\FirewallDashboard.ps1 .\FirewallDashboard.exe -noConsole -requireAdmin
```

### ⚠️ Cheklovlar

- Trafik statistikasi saqlanmaydi. 30 kunlik tarix uchun *Settings → Network & internet → Data usage* bo'limiga qarang.
- Lokal tarmoq trafigi ham sanaladi, masalan NAS'ga fayl ko'chirish.
- `C:\Windows` ichidagi dasturlarni bloklash ataylab taqiqlangan, chunki bu tizimni buzishi mumkin.
- Ba'zi brauzerlar DNS-over-HTTPS ishlatadi va u `hosts` fayli orqali bloklashni chetlab o'tishi mumkin. Bunday holda brauzerda secure DNS'ni o'chiring yoki IP bo'yicha ham bloklang.

### ⚖️ Ogohlantirish

Bu vosita o'zingizga tegishli yoki boshqarishga ruxsatingiz bo'lgan kompyuter va tarmoqlarda ishlatish uchun mo'ljallangan. Firewall'ni o'chirish yoki qoidalarni o'chirib tashlash tizim himoyasini pasaytiradi, shuning uchun ehtiyotkorlik bilan foydalaning.

---

## 📁 Repository structure / Repo tuzilishi

```
├── FirewallDashboard.ps1   # Main script / Asosiy skript
├── Launcher.cs             # EXE wrapper source / EXE launcher manba kodi
├── README.md
└── LICENSE
```

## 📄 License / Litsenziya

[MIT](LICENSE) © Umid Norbekov (Zerosec)
