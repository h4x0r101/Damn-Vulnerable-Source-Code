/*
 * ViewModels.cs — VulnApp v1.0.2
 * ASP.NET Core 8.0 | C# Models
 * Internal build: app-server-01 | 192.168.1.105
 *
 * VULNERABILITY #10: Internal server info in file header
 * VULNERABILITY #11: Version info in comments
 */

namespace VulnApp.Models;

// -------------------------------------------------------
// Login / Signup ViewModels
// -------------------------------------------------------
public class LoginViewModel
{
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string? ErrorMessage { get; set; }
}

public class SignupViewModel
{
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string Email    { get; set; } = "";
    public string? ErrorMessage   { get; set; }
    public string? SuccessMessage { get; set; }
}

// -------------------------------------------------------
// PII / Homepage ViewModel
// VULNERABILITY #3: These same fields are also passed via URL query string
// -------------------------------------------------------
public class HomepageViewModel
{
    public string  Username  { get; set; } = "";
    public string? Search    { get; set; }
    public string? Status    { get; set; }
    public string? Success   { get; set; }
    // VULNERABILITY #2: Internal IP exposed as a model property rendered in views
    public string  InternalIp { get; set; } = "192.168.1.105";

    public List<MessageModel> Messages   { get; set; } = new();
    public PiiModel?          PiiRecord  { get; set; }
    public int?               ViewUserId { get; set; }

    // URL-reflected PII fields (VULNERABILITY #3)
    public string? UrlName { get; set; }
    public string? UrlCc   { get; set; }
    public string? UrlSsn  { get; set; }
    public string? UrlCvv  { get; set; }
}

// -------------------------------------------------------
// Database Models
// -------------------------------------------------------
public class UserModel
{
    public int    Id       { get; set; }
    public string Username { get; set; } = "";
    // VULNERABILITY #1/#10: Password stored and passed in plaintext
    public string Password { get; set; } = "";
    public string Email    { get; set; } = "";
    public string Role     { get; set; } = "user";
}

public class PiiModel
{
    public int    Id        { get; set; }
    public int    UserId    { get; set; }
    public string FullName  { get; set; } = "";
    public string Dob       { get; set; } = "";
    public string Ssn       { get; set; } = "";
    public string CcNumber  { get; set; } = "";
    public string CcCvv     { get; set; } = "";
    public string CcExpiry  { get; set; } = "";
    public string Address   { get; set; } = "";
}

public class MessageModel
{
    public int    Id        { get; set; }
    public int    UserId    { get; set; }
    // VULNERABILITY #6: Message content stored raw — no sanitisation
    public string Message   { get; set; } = "";
    public string CreatedAt { get; set; } = "";
}

// -------------------------------------------------------
// Admin Panel ViewModel
// -------------------------------------------------------
public class AdminPanelViewModel
{
    public List<UserModel> Users      { get; set; } = new();
    public List<PiiModel>  PiiRecords { get; set; } = new();
    // VULNERABILITY #2: Internal IPs in model
    public string InternalIp { get; set; } = "192.168.1.105";
    public string DbHost     { get; set; } = "10.0.0.22";
}

// -------------------------------------------------------
// Error ViewModel
// VULNERABILITY #12: Full stack trace and SQL query exposed via this model
// -------------------------------------------------------
public class ErrorViewModel
{
    public string? ErrorMessage { get; set; }
    public string? StackTrace   { get; set; }
    public string? Query        { get; set; }
    public string? RequestPath  { get; set; }
}
