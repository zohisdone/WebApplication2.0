using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using WebApplication1.Models;
using WebApplication1.Data;

namespace WebApplication1.Pages.Account
{
    public class LogoutModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly AuthDbContext _db;

        public LogoutModel(SignInManager<ApplicationUser> signInManager, AuthDbContext db)
        {
            _signInManager = signInManager;
            _db = db;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _signInManager.UserManager.GetUserAsync(User);
            await _signInManager.SignOutAsync();

            if (user != null)
            {
                _db.AuditLogs.Add(new Models.AuditLog
                {
                    UserId = user.Id,
                    Event = "Logout",
                    IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                    OccurredAt = DateTime.UtcNow
                });
                await _db.SaveChangesAsync();
            }

            return LocalRedirect("/");
        }
    }
}
