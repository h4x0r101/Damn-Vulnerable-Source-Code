/*
 * AdminController.cs — VulnApp v1.0.2
 * ASP.NET Core 8.0 | Admin Controller
 *
 * VULNERABILITY #7:  Forced browsing — admin panel accessible without proper role check
 * VULNERABILITY #10: Infrastructure details in source comments
 * VULNERABILITY #12: Stack traces exposed on errors
 *
 * Internal: DB Host=10.0.0.22:5432 | App Server=192.168.1.105
 */

using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using VulnApp.Models;

namespace VulnApp.Controllers;

public class AdminController : Controller
{
    private readonly IConfiguration _config;

    // VULNERABILITY #2: Internal IP in source
    private const string InternalServerIp = "192.168.1.105";
    private const string DbHost           = "10.0.0.22";

    public AdminController(IConfiguration config)
    {
        _config = config;
    }

    private string GetConnectionString() =>
        _config.GetConnectionString("DefaultConnection") ?? "Data Source=Data/vulnapp.db";

    // ================================================================
    // ADMIN PANEL
    // Route: /Admin/AdminPanel
    // ================================================================
    [HttpGet]
    public IActionResult AdminPanel()
    {
        // -------------------------------------------------------
        // VULNERABILITY #7: Extremely weak authorisation check
        // Only checks if "AdminAuth" session string == "true".
        // An attacker who can manipulate session storage bypasses this entirely.
        // No role-based access control, no server-side verification.
        // -------------------------------------------------------
        string? adminAuth = HttpContext.Session.GetString("AdminAuth");
        if (adminAuth != "true")
            return RedirectToAction("SecretLogin", "Home");

        var vm = new AdminPanelViewModel
        {
            InternalIp = InternalServerIp,
            DbHost     = DbHost,
        };

        try
        {
            using var conn = new SqliteConnection(GetConnectionString());
            conn.Open();

            // Fetch all users — including plaintext passwords (VULNERABILITY #1)
            var userCmd = conn.CreateCommand();
            userCmd.CommandText = "SELECT * FROM users";
            using var userReader = userCmd.ExecuteReader();
            while (userReader.Read())
            {
                vm.Users.Add(new UserModel
                {
                    Id       = userReader.GetInt32(0),
                    Username = userReader.GetString(1),
                    Password = userReader.GetString(2), // VULNERABILITY #1: plaintext password
                    Email    = userReader.IsDBNull(3) ? "" : userReader.GetString(3),
                    Role     = userReader.IsDBNull(4) ? "user" : userReader.GetString(4),
                });
            }

            // Fetch all PII records
            var piiCmd = conn.CreateCommand();
            piiCmd.CommandText = "SELECT * FROM pii_data";
            using var piiReader = piiCmd.ExecuteReader();
            while (piiReader.Read())
            {
                vm.PiiRecords.Add(new PiiModel
                {
                    Id       = piiReader.GetInt32(0),
                    UserId   = piiReader.GetInt32(1),
                    FullName = piiReader.IsDBNull(2) ? "" : piiReader.GetString(2),
                    Dob      = piiReader.IsDBNull(3) ? "" : piiReader.GetString(3),
                    Ssn      = piiReader.IsDBNull(4) ? "" : piiReader.GetString(4),
                    CcNumber = piiReader.IsDBNull(5) ? "" : piiReader.GetString(5),
                    CcCvv    = piiReader.IsDBNull(6) ? "" : piiReader.GetString(6),
                    CcExpiry = piiReader.IsDBNull(7) ? "" : piiReader.GetString(7),
                    Address  = piiReader.IsDBNull(8) ? "" : piiReader.GetString(8),
                });
            }
        }
        catch (Exception ex)
        {
            // VULNERABILITY #12: Full stack trace exposed to user
            var errorVm = new ErrorViewModel
            {
                ErrorMessage = ex.Message,
                StackTrace   = ex.ToString(),
                RequestPath  = HttpContext.Request.Path
            };
            return View("~/Views/Shared/cust_error.cshtml", errorVm);
        }

        return View(vm);
    }
}
