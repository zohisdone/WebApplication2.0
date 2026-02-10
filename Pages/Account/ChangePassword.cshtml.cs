using System.ComponentModel.DataAnnotations;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using WebApplication1.Data;
using WebApplication1.Models;

namespace WebApplication1.Pages.Account
{
    [Authorize]
    public class ChangePasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly AuthDbContext _db;
        private readonly IPasswordHasher<ApplicationUser> _passwordHasher;

        public ChangePasswordModel(
            UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            AuthDbContext db,
            IPasswordHasher<ApplicationUser> passwordHasher)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _db = db;
            _passwordHasher = passwordHasher;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public class InputModel
        {
            [Required]
            [DataType(DataType.Password)]
            [Display(Name = "Current password")]
            public string CurrentPassword { get; set; } = null!;

            [Required]
            [DataType(DataType.Password)]
            [StringLength(100, MinimumLength = 12)]
            [Display(Name = "New password")]
            public string NewPassword { get; set; } = null!;

            [Required]
            [DataType(DataType.Password)]
            [Compare(nameof(NewPassword), ErrorMessage = "The new password and confirmation do not match.")]
            [Display(Name = "Confirm new password")]
            public string ConfirmPassword { get; set; } = null!;
        }

        private static readonly Regex PasswordRegex = new(@"^(?=.{12,}$)(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*\W).*$");

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                // Show validation errors inline as well as a modal summary
                TempData["ModalTitle"] = "Validation error";
                TempData["ModalBody"] = "Please check the form for errors and try again.";
                return RedirectToPage();
            }

            if (!PasswordRegex.IsMatch(Input.NewPassword))
            {
                TempData["ModalTitle"] = "Invalid password";
                TempData["ModalBody"] = "Password must be at least 12 characters and include uppercase, lowercase, number and special character.";
                return RedirectToPage();
            }

            var user = await _userManager.GetUserAsync(User);
            if (user == null)
            {
                await _signInManager.SignOutAsync();
                return RedirectToPage("/Account/Login");
            }

            // Prevent new password being same as current
            var currentVerification = _passwordHasher.VerifyHashedPassword(user, user.PasswordHash ?? string.Empty, Input.NewPassword);
            if (currentVerification != PasswordVerificationResult.Failed)
            {
                TempData["ModalTitle"] = "Invalid password";
                TempData["ModalBody"] = "New password must not be the same as your current password.";
                return RedirectToPage();
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
                    TempData["ModalTitle"] = "Invalid password";
                    TempData["ModalBody"] = "New password cannot match your last two passwords.";
                    return RedirectToPage();
                }
            }

            var oldHashed = user.PasswordHash;
            var changeResult = await _userManager.ChangePasswordAsync(user, Input.CurrentPassword, Input.NewPassword);
            if (!changeResult.Succeeded)
            {
                // Aggregate errors
                var msgs = changeResult.Errors.Select(e => e.Description).ToArray();
                TempData["ModalTitle"] = "Password change failed";
                TempData["ModalBody"] = string.Join(" ", msgs);
                return RedirectToPage();
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

            // Force logout after password change and show modal message on redirected page
            _db.AuditLogs.Add(new AuditLog
            {
                UserId = user.Id,
                Event = "ChangePassword",
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                OccurredAt = DateTime.UtcNow
            });
            await _db.SaveChangesAsync();

            await _signInManager.SignOutAsync();

            TempData["ModalTitle"] = "Password changed";
            TempData["ModalBody"] = "Your password has been changed. Please log in again.";

            return RedirectToPage("/Index");
        }
    }
}
