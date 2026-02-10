using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Models;
using WebApplication1.Data;

namespace WebApplication1.Pages.Account
{
    public class ShowRecoveryCodesModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;

        public ShowRecoveryCodesModel(UserManager<ApplicationUser> userManager, AuthDbContext db)
        {
            _userManager = userManager;
            _db = db;
        }

        public IEnumerable<string>? Codes { get; set; }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Challenge();

            var codes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            Codes = codes;

            _db.AuditLogs.Add(new Models.AuditLog { UserId = user.Id, Event = "2FA_RecoveryCodesGenerated", OccurredAt = DateTime.UtcNow, IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() });
            await _db.SaveChangesAsync();

            return Page();
        }

        public async Task<IActionResult> OnPostDownloadAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Challenge();

            var codes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            var content = string.Join("\r\n", codes);
            var bytes = System.Text.Encoding.UTF8.GetBytes(content);
            var filename = $"recovery-codes-{user.UserName}-{DateTime.UtcNow:yyyyMMddHHmmss}.txt";

            _db.AuditLogs.Add(new Models.AuditLog { UserId = user.Id, Event = "2FA_RecoveryCodesDownloaded", OccurredAt = DateTime.UtcNow, IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() });
            await _db.SaveChangesAsync();

            return File(bytes, "text/plain", filename);
        }
    }
}
