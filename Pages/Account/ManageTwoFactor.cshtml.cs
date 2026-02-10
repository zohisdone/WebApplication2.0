using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Models;
using WebApplication1.Data;

namespace WebApplication1.Pages.Account
{
    public class ManageTwoFactorModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;

        public ManageTwoFactorModel(UserManager<ApplicationUser> userManager, AuthDbContext db)
        {
            _userManager = userManager;
            _db = db;
        }

        public bool Is2faEnabled { get; set; }

        public async Task OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            Is2faEnabled = user != null && await _userManager.GetTwoFactorEnabledAsync(user);
        }

        public async Task<IActionResult> OnPostDisableAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Challenge();

            await _userManager.SetTwoFactorEnabledAsync(user, false);
            _db.AuditLogs.Add(new Models.AuditLog { UserId = user.Id, Event = "2FA_Disabled", OccurredAt = DateTime.UtcNow, IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() });
            await _db.SaveChangesAsync();

            TempData["StatusMessage"] = "Two-factor authentication has been disabled.";
            return RedirectToPage();
        }
    }
}
