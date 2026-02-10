using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Data;
using WebApplication1.Models;

namespace WebApplication1.Pages.Account
{
    public class ResetPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;
        private readonly IPasswordHasher<ApplicationUser> _passwordHasher;
        private readonly SignInManager<ApplicationUser> _signInManager;

        public ResetPasswordModel(
            UserManager<ApplicationUser> userManager,
            AuthDbContext db,
            IPasswordHasher<ApplicationUser> passwordHasher,
            SignInManager<ApplicationUser> signInManager)
        {
            _userManager = userManager;
            _db = db;
            _passwordHasher = passwordHasher;
            _signInManager = signInManager;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public class InputModel
        {
            [Required, EmailAddress]
            public string Email { get; set; } = null!;

            [Required]
            public string Token { get; set; } = null!;

            [Required, DataType(DataType.Password)]
            [StringLength(100, MinimumLength = 12)]
            public string NewPassword { get; set; } = null!;

            [Required, DataType(DataType.Password), Compare(nameof(NewPassword))]
            public string ConfirmPassword { get; set; } = null!;
        }

        private static readonly Regex PasswordRegex = new(@"^(?=.{12,}$)(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*\W).*$");

        public void OnGet(string? token = null, string? email = null)
        {
            Input.Token = token ?? string.Empty;
            Input.Email = email ?? string.Empty;
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();

            if (!PasswordRegex.IsMatch(Input.NewPassword))
            {
                ModelState.AddModelError(nameof(Input.NewPassword), "Password must be at least 12 characters and include uppercase, lowercase, number and special character.");
                return Page();
            }

            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null)
            {
                TempData["StatusMessage"] = "If an account with that email exists, a reset was attempted. Please check your email.";
                return RedirectToPage("/Account/Login");
            }

            var currVerify = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash ?? string.Empty, Input.NewPassword);
            if (currVerify != PasswordVerificationResult.Failed)
            {
                ModelState.AddModelError(nameof(Input.NewPassword), "New password cannot be the same as your current password.");
                return Page();
            }

            var lastTwo = _db.PasswordHistories
                             .Where(ph => ph.UserId == user.Id)
                             .OrderByDescending(ph => ph.CreatedAt)
                             .Take(2)
                             .Select(ph => ph.HashedPassword)
                             .ToList();

            foreach (var hashed in lastTwo)
            {
                if (_passwordHasher.VerifyHashedPassword(user, hashed, Input.NewPassword) != PasswordVerificationResult.Failed)
                {
                    ModelState.AddModelError(nameof(Input.NewPassword), "New password cannot match your last two passwords.");
                    return Page();
                }
            }

            var oldHashed = user.PasswordHash;
            var resetResult = await _userManager.ResetPasswordAsync(user, Input.Token, Input.NewPassword);
            if (!resetResult.Succeeded)
            {
                foreach (var err in resetResult.Errors)
                {
                    ModelState.AddModelError(string.Empty, err.Description);
                }
                return Page();
            }

            if (!string.IsNullOrEmpty(oldHashed))
            {
                _db.PasswordHistories.Add(new PasswordHistory
                {
                    UserId = user.Id,
                    HashedPassword = oldHashed,
                    CreatedAt = DateTime.UtcNow
                });
            }

            var histories = _db.PasswordHistories
                              .Where(ph => ph.UserId == user.Id)
                              .OrderByDescending(ph => ph.CreatedAt)
                              .ToList();

            if (histories.Count > 2)
            {
                var toRemove = histories.Skip(2).ToList();
                _db.PasswordHistories.RemoveRange(toRemove);
            }

            await _db.SaveChangesAsync();

            await _userManager.UpdateSecurityStampAsync(user);
            await _signInManager.RefreshSignInAsync(user);

            _db.AuditLogs.Add(new AuditLog
            {
                UserId = user.Id,
                Event = "ResetPassword",
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                OccurredAt = DateTime.UtcNow
            });
            await _db.SaveChangesAsync();

            TempData["StatusMessage"] = "Your password has been reset successfully.";
            return RedirectToPage("/Account/Login");
        }
    }
}
