using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using WebApplication1.Data;
using WebApplication1.Models;
using WebApplication1.Services;
using WebApplication1.Middleware;
using Microsoft.Extensions.Options;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();

// Bind password policy
builder.Services.Configure<PasswordPolicyOptions>(builder.Configuration.GetSection("PasswordPolicy"));

// Configure DbContext with SQL Server
var connectionString = builder.Configuration.GetConnectionString("AuthConnectionString") ?? builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<AuthDbContext>(options => options.UseSqlServer(connectionString));

// Identity with ApplicationUser
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Password policy
    options.Password.RequiredLength = 12;
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = true;

    // Lockout
    options.Lockout.MaxFailedAccessAttempts = 3;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.AllowedForNewUsers = true;

    options.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<AuthDbContext>()
.AddDefaultTokenProviders();

// Cookie settings
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.Always;
    options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(30);
    options.SlidingExpiration = true;
    options.LoginPath = "/Account/Login";
    options.AccessDeniedPath = "/Error/Error403";
});

// Data protection
builder.Services.AddDataProtection();

// Register services
builder.Services.AddScoped<IEncryptionService, DataProtectorEncryptionService>();
builder.Services.AddHttpClient<RecaptchaService>();
builder.Services.AddScoped<IRecaptchaService, RecaptchaService>();
builder.Services.AddTransient<IEmailSender, SmtpEmailSender>();
builder.Services.AddScoped<UserSessionService>();

// Add a simple backup hosted service
builder.Services.AddHostedService<SimpleBackupService>();

var app = builder.Build();

// Configure middleware pipeline
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

// Custom status code pages
app.UseStatusCodePagesWithReExecute("/Error/Error{0}");

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

// Single session middleware
app.UseMiddleware<SingleSessionMiddleware>();

app.MapRazorPages();

app.Run();

// Password policy options type
public class PasswordPolicyOptions
{
    public int MinAgeDays { get; set; }
    public int MaxAgeDays { get; set; }
}

// Simple backup hosted service - performs periodic copy of MDF/LDF if present (development convenience)
public class SimpleBackupService : IHostedService, IDisposable
{
    private Timer? _timer;
    private readonly IConfiguration _config;
    private readonly IWebHostEnvironment _env;

    public SimpleBackupService(IConfiguration config, IWebHostEnvironment env)
    {
        _config = config;
        _env = env;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        // Run every hour
        _timer = new Timer(DoBackup, null, TimeSpan.FromMinutes(1), TimeSpan.FromHours(1));
        return Task.CompletedTask;
    }

    private void DoBackup(object? state)
    {
        try
        {
            var userProfile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var mdf = Path.Combine(userProfile, "AspNetAuth_v2.mdf");
            var ldf = Path.Combine(userProfile, "AspNetAuth_v2_log.ldf");
            var backups = Path.Combine(_env.ContentRootPath, "backups");
            Directory.CreateDirectory(backups);

            if (File.Exists(mdf))
            {
                var dest = Path.Combine(backups, "AspNetAuth_v2_" + DateTime.UtcNow.ToString("yyyyMMddHHmmss") + ".mdf");
                File.Copy(mdf, dest, true);
            }
            if (File.Exists(ldf))
            {
                var dest = Path.Combine(backups, "AspNetAuth_v2_log_" + DateTime.UtcNow.ToString("yyyyMMddHHmmss") + ".ldf");
                File.Copy(ldf, dest, true);
            }
        }
        catch
        {
            // ignore errors in backup service
        }
    }

    public Task StopAsync(CancellationToken cancellationToken)
    {
        _timer?.Change(Timeout.Infinite, 0);
        return Task.CompletedTask;
    }

    public void Dispose()
    {
        _timer?.Dispose();
    }
}
