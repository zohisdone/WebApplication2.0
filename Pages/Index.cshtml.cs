using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using WebApplication1.Models;
using WebApplication1.Services;
using WebApplication1.Data;

namespace WebApplication1.Pages
{
    public class IndexModel : PageModel
    {
        private readonly ILogger<IndexModel> _logger;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEncryptionService _enc;
        private readonly AuthDbContext _db;

        public IndexModel(ILogger<IndexModel> logger, UserManager<ApplicationUser> userManager, IEncryptionService enc, AuthDbContext db)
        {
            _logger = logger;
            _userManager = userManager;
            _enc = enc;
            _db = db;
        }

        public string? FullName { get; set; }
        public string? Email { get; set; }
        public string? DecryptedNRIC { get; set; }
        public List<Models.AuditLog>? RecentAuditLogs { get; set; }
        public DateTime? DateOfBirth { get; set; }
        public string? ResumeUrl { get; set; }

        public async Task OnGetAsync()
        {
            if (User?.Identity?.IsAuthenticated == true)
            {
                var user = await _userManager.GetUserAsync(User);
                if (user != null)
                {
                    FullName = string.Join(' ', new[] { user.FirstName, user.LastName }.Where(s => !string.IsNullOrWhiteSpace(s)));
                    Email = user.Email;
                    DateOfBirth = user.DateOfBirth;
                    ResumeUrl = string.IsNullOrWhiteSpace(user.ResumeFilePath) ? null : Url.Content(user.ResumeFilePath);
                    try
                    {
                        DecryptedNRIC = string.IsNullOrEmpty(user.EncryptedNRIC) ? null : _enc.Unprotect(user.EncryptedNRIC);
                    }
                    catch
                    {
                        DecryptedNRIC = "[decryption failed]";
                    }

                    RecentAuditLogs = _db.AuditLogs
                        .Where(a => a.UserId == user.Id)
                        .OrderByDescending(a => a.OccurredAt)
                        .Take(10)
                        .ToList();
                }
            }
            else
            {
                RecentAuditLogs = new List<Models.AuditLog>();
            }
        }
    }
}
