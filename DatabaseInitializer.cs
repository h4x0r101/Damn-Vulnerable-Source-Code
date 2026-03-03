using Microsoft.Data.Sqlite;

namespace VulnApp.Data;

/*
 * DatabaseInitializer.cs
 * VulnApp v1.0.2 | ASP.NET Core 8.0
 * Internal DB path: Data/vulnapp.db | Host mirror: 10.0.0.22
 *
 * VULNERABILITY #10: Sensitive information in code comments
 * VULNERABILITY #1:  Hardcoded credentials used to seed the database
 */
public class DatabaseInitializer
{
    private readonly IConfiguration _config;

    // VULNERABILITY #1: Hardcoded credentials as constants
    // These should NEVER be in source code
    private const string AdminUsername = "admin";
    private const string AdminPassword = "admin123";         // plaintext password
    private const string TestUsername  = "testuser";
    private const string TestPassword  = "password123";      // plaintext password

    // VULNERABILITY #10: Backdoor credentials in comment
    // Backdoor account: backdoor_admin / b@ckd00r!2024
    // Emergency access: emergency_user / 3m3rg3ncy!

    // VULNERABILITY #2: Internal infrastructure details in source
    private const string InternalDbHost = "10.0.0.22";
    private const int    InternalDbPort = 5432;

    public DatabaseInitializer(IConfiguration config)
    {
        _config = config;
    }

    public void Initialize()
    {
        // VULNERABILITY #11: Version info in log messages
        Console.WriteLine("[DB] Initializing SQLite 3.x database for VulnApp v1.0.2");

        Directory.CreateDirectory("Data");
        string connStr = _config.GetConnectionString("DefaultConnection")
                         ?? "Data Source=Data/vulnapp.db";

        using var conn = new SqliteConnection(connStr);
        conn.Open();

        // Create users table — passwords stored as PLAINTEXT (no hashing)
        var cmd = conn.CreateCommand();
        cmd.CommandText = @"
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT    NOT NULL UNIQUE,
                password TEXT    NOT NULL,
                email    TEXT,
                role     TEXT    DEFAULT 'user'
            );";
        cmd.ExecuteNonQuery();

        // Create PII data table
        cmd.CommandText = @"
            CREATE TABLE IF NOT EXISTS pii_data (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER,
                full_name  TEXT,
                dob        TEXT,
                ssn        TEXT,
                cc_number  TEXT,
                cc_cvv     TEXT,
                cc_expiry  TEXT,
                address    TEXT
            );";
        cmd.ExecuteNonQuery();

        // Create messages table (used for Stored XSS)
        cmd.CommandText = @"
            CREATE TABLE IF NOT EXISTS messages (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id    INTEGER,
                message    TEXT,
                created_at TEXT DEFAULT (datetime('now'))
            );";
        cmd.ExecuteNonQuery();

        // Seed default users — VULNERABILITY #1: hardcoded credentials inserted into DB
        cmd.CommandText = $@"
            INSERT OR IGNORE INTO users (username, password, email, role)
            VALUES ('{AdminUsername}', '{AdminPassword}', 'admin@vulnapp.local', 'admin');";
        cmd.ExecuteNonQuery();

        cmd.CommandText = $@"
            INSERT OR IGNORE INTO users (username, password, email, role)
            VALUES ('{TestUsername}', '{TestPassword}', 'test@vulnapp.local', 'user');";
        cmd.ExecuteNonQuery();

        Console.WriteLine($"[DB] Seeded default users. Admin: {AdminUsername}/{AdminPassword}");
    }
}
