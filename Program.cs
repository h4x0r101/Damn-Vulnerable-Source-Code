/*
 * VulnApp - Intentionally Vulnerable ASP.NET Core Application
 * For Educational / Security Research Purposes Only
 * Version: 1.0.2 (ASP.NET Core 8.0, C#)
 * Author: OWASP Training Project
 * Internal Network: 192.168.1.105
 * Database: SQLite - Data/vulnapp.db
 *
 * VULNERABILITY #2: Internal IP hardcoded in file header comment
 * VULNERABILITY #11: Framework and version details disclosed in comments
 */

using Microsoft.AspNetCore.Authentication.Cookies;
using VulnApp.Data;

// -------------------------------------------------------
// VULNERABILITY #11: Version printed to console on startup
// -------------------------------------------------------
Console.WriteLine("[*] VulnApp v1.0.2 starting...");
Console.WriteLine("[*] ASP.NET Core 8.0 | C# | SQLite");
// VULNERABILITY #2: Internal IP printed to console/logs
Console.WriteLine("[*] Binding to http://192.168.1.105:5000");

var builder = WebApplication.CreateBuilder(args);

// Add MVC with Views
builder.Services.AddControllersWithViews(options =>
{
    // VULNERABILITY #12: Developer exception page enabled in all environments
    // Should be restricted to Development only
});

// VULNERABILITY #1: Hardcoded session secret key
// Should be loaded from environment variables or a secrets manager
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);
    // VULNERABILITY #1: Insecure session cookie config
    options.Cookie.HttpOnly = false;   // Should be true
    options.Cookie.SecurePolicy = CookieSecurePolicy.None; // Should be Always
    options.Cookie.SameSite = SameSiteMode.None;
});

// VULNERABILITY #1: Hardcoded secret key in source code
builder.Services.AddAntiforgery(options =>
{
    options.Cookie.Name = "VulnApp.Antiforgery";
    options.Cookie.SecurePolicy = CookieSecurePolicy.None;
});

// Initialize SQLite database
builder.Services.AddSingleton<DatabaseInitializer>();

var app = builder.Build();

// VULNERABILITY #12: Developer exception page enabled unconditionally
// Exposes full stack traces to end users in all environments
app.UseDeveloperExceptionPage();

// VULNERABILITY #11: Server header discloses version info
// No call to app.UseHsts() or header stripping

app.UseStaticFiles();
app.UseRouting();
app.UseSession();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// Initialize the database on startup
var dbInit = app.Services.GetRequiredService<DatabaseInitializer>();
dbInit.Initialize();

// VULNERABILITY #2 + #11: Startup info with internal IP and versions
Console.WriteLine("[*] Database initialized at Data/vulnapp.db");
Console.WriteLine("[*] App running - http://192.168.1.105:5000 | ASP.NET Core/8.0.0");

app.Run("http://0.0.0.0:5000");
