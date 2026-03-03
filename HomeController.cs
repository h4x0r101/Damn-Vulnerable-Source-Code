/*
 * HomeController.cs — VulnApp v1.0.2
 * ASP.NET Core 8.0 | MVC Controller
 *
 * VULNERABILITY #1:  Hardcoded admin credentials as constants
 * VULNERABILITY #2:  Internal IP/infrastructure details in source
 * VULNERABILITY #4:  Insecure random used for session token generation
 * VULNERABILITY #5:  Reflected XSS via unencoded query param in View
 * VULNERABILITY #6:  Stored XSS — messages saved & rendered without sanitisation
 * VULNERABILITY #7:  Forced browsing / authorisation bypass
 * VULNERABILITY #8:  IDOR — user-controlled ID used in DB query without ownership check
 * VULNERABILITY #9:  SQL injection — string-concatenated query in login
 * VULNERABILITY #10: Sensitive info in comments throughout this file
 * VULNERABILITY #11: Version and framework info exposed
 * VULNERABILITY #12: Full exception stack traces returned to user
 */

using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using VulnApp.Models;

namespace VulnApp.Controllers;

public class HomeController : Controller
{
    private readonly IConfiguration _config;
    private readonly ILogger<HomeController> _logger;

    // -------------------------------------------------------
    // VULNERABILITY #1: Hardcoded admin credentials in controller
    // VULNERABILITY #10: Backdoor credentials in comment
    // Backdoor: backdoor_admin / b@ckd00r!2024
    // -------------------------------------------------------
    private const string AdminUsername = "admin";
    private const string AdminPassword = "SuperSecret@123";

    // VULNERABILITY #2: Internal infrastructure details hardcoded
    private const string InternalServerIp = "192.168.1.105";
    private const string DbHost           = "10.0.0.22";
    private const int    DbPort           = 5432;

    public HomeController(IConfiguration config, ILogger<HomeController> logger)
    {
        _config = config;
        _logger = logger;
    }

    private string GetConnectionString() =>
        _config.GetConnectionString("DefaultConnection") ?? "Data Source=Data/vulnapp.db";

    // -------------------------------------------------------
    // VULNERABILITY #4: Insecure random for session token
    // System.Random is NOT cryptographically secure.
    // Should use: RandomNumberGenerator.GetBytes() or Guid.NewGuid()
    // -------------------------------------------------------
    private static string GenerateSessionToken()
    {
        // BUG: Only 900,000 possible values — trivially brute-forceable
        var rng = new Random();
        return rng.Next(100000, 999999).ToString();
    }

    // ================================================================
    // INDEX — Sign In (GET + POST)
    // Route: / and /index.html
    // ================================================================
    [HttpGet]
    [Route("/")]
    [Route("/index.html")]
    public IActionResult Index()
    {
        return View(new LoginViewModel());
    }

    [HttpPost]
    [Route("/")]
    [Route("/index.html")]
    public IActionResult Index(LoginViewModel model)
    {
        string query = "";
        try
        {
            using var conn = new SqliteConnection(GetConnectionString());
            conn.Open();

            // -------------------------------------------------------
            // VULNERABILITY #9: SQL Injection — Authentication Bypass
            // User input concatenated directly into SQL string.
            // Bypass payload: username = ' OR '1'='1' --
            // -------------------------------------------------------
            query = $"SELECT * FROM users WHERE username='{model.Username}' AND password='{model.Password}'";
            var cmd = conn.CreateCommand();
            cmd.CommandText = query;

            using var reader = cmd.ExecuteReader();
            if (reader.Read())
            {
                int    userId   = reader.GetInt32(0);
                string username = reader.GetString(1);
                string role     = reader.GetString(4);

                // VULNERABILITY #4: Insecure random token
                string token = GenerateSessionToken();

                HttpContext.Session.SetInt32("UserId",   userId);
                HttpContext.Session.SetString("Username", username);
                HttpContext.Session.SetString("Role",     role);
                HttpContext.Session.SetString("Token",    token);

                return RedirectToAction("Homepage");
            }
            else
            {
                model.ErrorMessage = "Invalid username or password.";
                return View(model);
            }
        }
        catch (Exception ex)
        {
            // -------------------------------------------------------
            // VULNERABILITY #12: Full exception detail returned to user
            // Stack trace, SQL query, and internal paths exposed
            // -------------------------------------------------------
            var errorVm = new ErrorViewModel
            {
                ErrorMessage = ex.Message,
                StackTrace   = ex.ToString(),   // full stack trace
                Query        = query,            // exposes SQL structure
                RequestPath  = HttpContext.Request.Path
            };
            return View("~/Views/Shared/cust_error.cshtml", errorVm);
        }
    }

    // ================================================================
    // SIGNUP — GET + POST
    // Route: /signup.html
    // ================================================================
    [HttpGet("/signup.html")]
    public IActionResult Signup() => View(new SignupViewModel());

    [HttpPost("/signup.html")]
    public IActionResult Signup(SignupViewModel model)
    {
        try
        {
            using var conn = new SqliteConnection(GetConnectionString());
            conn.Open();

            // Note: password stored in plaintext — no hashing
            var cmd = conn.CreateCommand();
            cmd.CommandText =
                "INSERT INTO users (username, password, email, role) VALUES (@u, @p, @e, 'user')";
            cmd.Parameters.AddWithValue("@u", model.Username);
            cmd.Parameters.AddWithValue("@p", model.Password);  // plaintext
            cmd.Parameters.AddWithValue("@e", model.Email);
            cmd.ExecuteNonQuery();

            model.SuccessMessage = "Account created! You can now sign in.";
        }
        catch (Exception ex)
        {
            // VULNERABILITY #12
            var errorVm = new ErrorViewModel
            {
                ErrorMessage = ex.Message,
                StackTrace   = ex.ToString(),
                RequestPath  = HttpContext.Request.Path
            };
            return View("~/Views/Shared/cust_error.cshtml", errorVm);
        }
        return View(model);
    }

    // ================================================================
    // HOMEPAGE — Dashboard / PII entry
    // Route: /homepage.html
    // ================================================================
    [HttpGet("/homepage.html")]
    public IActionResult Homepage()
    {
        // -------------------------------------------------------
        // VULNERABILITY #7: Weak authentication check
        // Only checks if session key exists — no role verification.
        // Direct navigation to /homepage.html bypasses intent.
        // -------------------------------------------------------
        if (HttpContext.Session.GetInt32("UserId") is null)
            return RedirectToAction("Index");

        string? search    = Request.Query["search"];
        string? status    = Request.Query["status"];
        int?    viewUser  = null;
        string? viewParam = Request.Query["view_user"];
        if (!string.IsNullOrEmpty(viewParam) && int.TryParse(viewParam, out int vu))
            viewUser = vu;

        int sessionUserId = HttpContext.Session.GetInt32("UserId") ?? 0;

        var vm = new HomepageViewModel
        {
            Username   = HttpContext.Session.GetString("Username") ?? "",
            Search     = search,
            Status     = status,
            InternalIp = InternalServerIp,
            ViewUserId = viewUser,
            // VULNERABILITY #3: PII fields read back from URL query string
            UrlName = Request.Query["name"],
            UrlCc   = Request.Query["cc"],
            UrlSsn  = Request.Query["ssn"],
            UrlCvv  = Request.Query["cvv"],
        };

        try
        {
            using var conn = new SqliteConnection(GetConnectionString());
            conn.Open();

            // -------------------------------------------------------
            // VULNERABILITY #8: IDOR — no ownership check on view_user
            // Any authenticated user can view any other user's PII
            // by changing the view_user query param.
            // -------------------------------------------------------
            int targetId = viewUser ?? sessionUserId;
            var piiCmd = conn.CreateCommand();
            piiCmd.CommandText = $"SELECT * FROM pii_data WHERE user_id = {targetId}";
            using var piiReader = piiCmd.ExecuteReader();
            if (piiReader.Read())
            {
                vm.PiiRecord = new PiiModel
                {
                    Id       = piiReader.GetInt32(0),
                    UserId   = piiReader.GetInt32(1),
                    FullName = piiReader.IsDBNull(2) ? "" : piiReader.GetString(2),
                    Ssn      = piiReader.IsDBNull(4) ? "" : piiReader.GetString(4),
                    CcNumber = piiReader.IsDBNull(5) ? "" : piiReader.GetString(5),
                };
            }

            // -------------------------------------------------------
            // VULNERABILITY #6: Stored XSS
            // Messages fetched from DB and rendered raw (Html.Raw) in the View
            // -------------------------------------------------------
            var msgCmd = conn.CreateCommand();
            msgCmd.CommandText = "SELECT * FROM messages ORDER BY created_at DESC LIMIT 20";
            using var msgReader = msgCmd.ExecuteReader();
            while (msgReader.Read())
            {
                vm.Messages.Add(new MessageModel
                {
                    Id        = msgReader.GetInt32(0),
                    UserId    = msgReader.GetInt32(1),
                    Message   = msgReader.IsDBNull(2) ? "" : msgReader.GetString(2),
                    CreatedAt = msgReader.IsDBNull(3) ? "" : msgReader.GetString(3),
                });
            }
        }
        catch (Exception ex)
        {
            // VULNERABILITY #12
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

    [HttpPost("/homepage.html")]
    public IActionResult HomepagePost(string action, string? full_name, string? dob, string? ssn,
        string? cc_number, string? cc_cvv, string? cc_expiry, string? address, string? message)
    {
        // VULNERABILITY #7: Same weak auth check
        if (HttpContext.Session.GetInt32("UserId") is null)
            return RedirectToAction("Index");

        int userId = HttpContext.Session.GetInt32("UserId") ?? 0;

        try
        {
            if (action == "submit_pii")
            {
                // -------------------------------------------------------
                // VULNERABILITY #3: PII data transferred via URL
                // Credit card, SSN, CVV redirected as plaintext GET params.
                // Exposed in: browser history, server access logs, referrer headers.
                // -------------------------------------------------------
                return Redirect(
                    $"/homepage.html?status=saved" +
                    $"&name={full_name}" +
                    $"&cc={cc_number}" +
                    $"&ssn={ssn}" +
                    $"&cvv={cc_cvv}");
            }
            else if (action == "post_message" && !string.IsNullOrEmpty(message))
            {
                // -------------------------------------------------------
                // VULNERABILITY #6: Stored XSS
                // Message stored raw — no HTML encoding or sanitisation.
                // Payload: <script>alert('StoredXSS')</script>
                // -------------------------------------------------------
                using var conn = new SqliteConnection(GetConnectionString());
                conn.Open();
                var cmd = conn.CreateCommand();
                cmd.CommandText =
                    "INSERT INTO messages (user_id, message) VALUES (@uid, @msg)";
                cmd.Parameters.AddWithValue("@uid", userId);
                cmd.Parameters.AddWithValue("@msg", message); // raw unsanitised input
                cmd.ExecuteNonQuery();
            }
        }
        catch (Exception ex)
        {
            // VULNERABILITY #12
            var errorVm = new ErrorViewModel
            {
                ErrorMessage = ex.Message,
                StackTrace   = ex.ToString(),
                RequestPath  = HttpContext.Request.Path
            };
            return View("~/Views/Shared/cust_error.cshtml", errorVm);
        }

        return RedirectToAction("Homepage");
    }

    // ================================================================
    // SECRET ADMIN LOGIN
    // Route: /sl.html — discoverable via forced browsing
    // ================================================================

    // VULNERABILITY #7: No rate limiting, no brute-force protection
    // VULNERABILITY #10: Secret path documented in comment
    // Secret page path: /sl.html | credentials: admin / SuperSecret@123
    [HttpGet("/sl.html")]
    public IActionResult SecretLogin() => View(new LoginViewModel());

    [HttpPost("/sl.html")]
    public IActionResult SecretLogin(LoginViewModel model)
    {
        // -------------------------------------------------------
        // VULNERABILITY #1: Auth compared against hardcoded constants
        // VULNERABILITY #4: Insecure random token for admin session
        // -------------------------------------------------------
        if (model.Username == AdminUsername && model.Password == AdminPassword)
        {
            HttpContext.Session.SetString("AdminAuth",  "true");
            HttpContext.Session.SetString("AdminToken", GenerateSessionToken()); // VULN #4
            return RedirectToAction("AdminPanel", "Admin");
        }

        model.ErrorMessage = "Access Denied.";
        return View(model);
    }

    // ================================================================
    // LOGOUT
    // ================================================================
    [HttpGet("/logout")]
    public IActionResult Logout()
    {
        HttpContext.Session.Clear();
        return RedirectToAction("Index");
    }
}
