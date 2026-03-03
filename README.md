# VulnApp — Intentionally Vulnerable ASP.NET Core Application (C#)

> **⚠ WARNING:** This application is **intentionally vulnerable**. It is for **educational and security research purposes only**. Do NOT deploy on a public server or production environment.

---

## Overview

This is the **C# / ASP.NET Core MVC** implementation of VulnApp — an open-source intentionally vulnerable web application for beginner security researchers to practice **manual source code review** without a running UI.

All 12 OWASP-based vulnerabilities from the original Python/Flask version are faithfully replicated, adapted to C# idioms so reviewers can compare vulnerability patterns across languages and frameworks.

---

## Application Structure

```
VulnApp/
├── Program.cs                         # App entry point, startup config, middleware
├── VulnApp.csproj                     # Project file (version info)
├── appsettings.json                   # Config — hardcoded secrets live here
├── Controllers/
│   ├── HomeController.cs              # Login, Signup, Homepage, SecretLogin, Logout
│   └── AdminController.cs             # Admin panel
├── Models/
│   └── ViewModels.cs                  # All view models and DB models
├── Data/
│   └── DatabaseInitializer.cs         # SQLite schema + seed data
├── Views/
│   ├── Home/
│   │   ├── Index.cshtml               # index.html — Sign In
│   │   ├── Signup.cshtml              # signup.html — Registration
│   │   ├── Homepage.cshtml            # homepage.html — User dashboard / PII forms
│   │   └── SecretLogin.cshtml         # sl.html — Secret admin login
│   ├── Admin/
│   │   └── AdminPanel.cshtml          # Admin panel
│   └── Shared/
│       ├── _Layout.cshtml             # Shared layout template
│       └── cust_error.cshtml          # cust_error.html — Error/stack trace dump
└── wwwroot/
    └── css/
        └── style.css                  # Shared stylesheet (same as Python version)
```

---

## Pages

| Page | Route | Description |
|------|-------|-------------|
| `index.html` | `/` or `/index.html` | Landing page with Sign In form |
| `signup.html` | `/signup.html` | Create a new user account |
| `homepage.html` | `/homepage.html` | Authenticated dashboard with PII data entry |
| `sl.html` | `/sl.html` | Secret admin login (forced browsing target) |
| Admin Panel | `/Admin/AdminPanel` | Admin panel — all users and PII data |
| `cust_error.html` | (error view) | Dumps full stack traces and SQL queries |

---

## Vulnerability List & C# Locations

### 1. 🔑 Hardcoded Secrets
**Files:** `appsettings.json`, `HomeController.cs`, `AdminController.cs`, `DatabaseInitializer.cs`
```csharp
// HomeController.cs
private const string AdminUsername = "admin";
private const string AdminPassword = "SuperSecret@123";
```
```json
// appsettings.json
"AdminPassword": "SuperSecret@123",
"SecretKey": "dev_secret_key_do_not_use_in_prod_abc123xyz"
```

---

### 2. 🌐 Internal IP Disclosure
**Files:** `Program.cs`, `HomeController.cs`, `AdminController.cs`, `DatabaseInitializer.cs`, all Views
```csharp
private const string InternalServerIp = "192.168.1.105";
private const string DbHost           = "10.0.0.22";
```
Also rendered into HTML via the `AdminPanelViewModel` and in Razor comments/footer.

---

### 3. 📋 PII Data Transferred via URL
**Files:** `HomeController.cs` (`HomepagePost`), `Views/Home/Homepage.cshtml`
```csharp
return Redirect(
    $"/homepage.html?status=saved&name={full_name}&cc={cc_number}&ssn={ssn}&cvv={cc_cvv}");
```
Credit card numbers, SSNs, and CVVs appear in the browser's address bar, history, and server access logs.

---

### 4. 🎲 Insecure Random Function
**Files:** `HomeController.cs` (`GenerateSessionToken`)
```csharp
// System.Random is NOT cryptographically secure
var rng = new Random();
return rng.Next(100000, 999999).ToString();
// Should use: RandomNumberGenerator.GetBytes() or Guid.NewGuid()
```

---

### 5. 🪞 Reflected XSS
**Files:** `HomeController.cs`, `Views/Home/Homepage.cshtml`
```csharp
// Razor view — Html.Raw() bypasses automatic encoding
@Html.Raw(Model.Search)
```
**Payload:** `?search=<script>alert('XSS')</script>`

---

### 6. 💾 Stored XSS
**Files:** `HomeController.cs` (`HomepagePost`), `Views/Home/Homepage.cshtml`
```csharp
// Stored raw in SQLite — no encoding, no sanitisation
cmd.Parameters.AddWithValue("@msg", message);
```
```csharp
// Rendered raw in view
@Html.Raw(msg.Message)
```
**Payload:** Post `<img src=x onerror=alert('StoredXSS')>` in the message form.

---

### 7. 🚪 Forced Browsing / Authorization Bypass
**Files:** `HomeController.cs`, `AdminController.cs`
- `/sl.html` is unlinked but directly accessible
- `/Admin/AdminPanel` only checks a simple session string `"AdminAuth" == "true"` — no role-based access control
- `/homepage.html` checks for session presence but not for valid role

---

### 8. 🔢 Insecure Direct Object Reference (IDOR)
**Files:** `HomeController.cs` (`Homepage` GET action)
```csharp
int targetId = viewUser ?? sessionUserId;  // viewUser comes from ?view_user= param
piiCmd.CommandText = $"SELECT * FROM pii_data WHERE user_id = {targetId}";
// No check that targetId belongs to the requesting user
```

---

### 9. 💉 SQL Injection — Authentication Bypass
**Files:** `HomeController.cs` (`Index` POST action)
```csharp
// Direct string interpolation into SQL query
query = $"SELECT * FROM users WHERE username='{model.Username}' AND password='{model.Password}'";
```
**Bypass payload:** Username: `' OR '1'='1' --` / Password: anything

---

### 10. 💬 Sensitive Information in Comments
**Files:** All `.cs` and `.cshtml` files  
Credentials, backdoor accounts, internal IPs, SQL query structures, and bypass hints are embedded throughout source code and Razor comments.

---

### 11. 🏷 Version Disclosure
**Files:** `Program.cs`, `VulnApp.csproj`, `appsettings.json`, `Views/Shared/_Layout.cshtml`, `cust_error.cshtml`
```csharp
Console.WriteLine("[*] ASP.NET Core 8.0 | C# | SQLite");
```
```html
<meta name="generator" content="VulnApp v1.0.2 ASP.NET Core/8.0 C#">
```

---

### 12. 🔍 Stack Trace / Technical Error Exposure
**Files:** `HomeController.cs`, `AdminController.cs`, `Views/Shared/cust_error.cshtml`, `Program.cs`
```csharp
// Full .NET stack trace passed to view
var errorVm = new ErrorViewModel
{
    ErrorMessage = ex.Message,
    StackTrace   = ex.ToString(),  // exposes full .NET call stack
    Query        = query,          // exposes raw SQL with injected input
};
```
Additionally, `app.UseDeveloperExceptionPage()` is called unconditionally in `Program.cs`.

---

## C# vs Python — Key Differences

| Aspect | Python/Flask | C# / ASP.NET Core |
|--------|-------------|-------------------|
| SQL Injection | f-string interpolation | String interpolation `$"..."` |
| XSS (Reflected) | `\|safe` Jinja2 filter | `@Html.Raw()` in Razor |
| XSS (Stored) | `\|safe` Jinja2 filter | `@Html.Raw()` in Razor |
| Insecure Random | `random.randint()` | `new Random().Next()` |
| Stack trace exposure | `traceback.format_exc()` | `ex.ToString()` + `UseDeveloperExceptionPage()` |
| Hardcoded secrets | Python constants | `const` fields + `appsettings.json` |
| Session token | `random.randint` | `new Random().Next()` |

---

## Setup & Run

### Prerequisites
- [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0)

### Run
```bash
dotnet run
```

The app will start at `http://0.0.0.0:5000`.

### Default Accounts
| Username | Password | Role |
|----------|----------|------|
| `admin` | `admin123` | admin |
| `testuser` | `password123` | user |

---

## Disclaimer

This application contains **intentional security vulnerabilities** for training purposes. The authors are not responsible for any misuse. Always run in an isolated, offline environment.
