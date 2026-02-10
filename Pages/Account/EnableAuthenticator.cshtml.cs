using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using QRCoder;
using WebApplication1.Models;
using WebApplication1.Data;

namespace WebApplication1.Pages.Account
{
    public class EnableAuthenticatorModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;

        public EnableAuthenticatorModel(UserManager<ApplicationUser> userManager, AuthDbContext db)
        {
            _userManager = userManager;
            _db = db;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public string? QrCodeImageUrl { get; set; }
        public string? FormattedKey { get; set; }

        public class InputModel
        {
            [Required]
            public string Code { get; set; } = null!;
        }

        public async Task<IActionResult> OnGetAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Challenge();

            var unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(unformattedKey))
            {
                await _userManager.ResetAuthenticatorKeyAsync(user);
                unformattedKey = await _userManager.GetAuthenticatorKeyAsync(user);
            }

            FormattedKey = unformattedKey; // could format for display

            var email = user.Email ?? user.UserName;
            var otpauth = $"otpauth://totp/AceJobAgency:{email}?secret={unformattedKey}&issuer=AceJobAgency&digits=6";

            using var qrGenerator = new QRCodeGenerator();
            var qrData = qrGenerator.CreateQrCode(otpauth, QRCodeGenerator.ECCLevel.Q);
            var qrCode = new PngByteQRCode(qrData);
            var qrBytes = qrCode.GetGraphic(20);
            QrCodeImageUrl = $"data:image/png;base64,{Convert.ToBase64String(qrBytes)}";

            return Page();
        }

        public async Task<IActionResult> OnPostAsync()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user == null) return Challenge();

            if (!ModelState.IsValid) return Page();

            var verificationCode = Input.Code.Replace(" ", string.Empty);
            var isValid = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, verificationCode);
            if (!isValid)
            {
                ModelState.AddModelError(string.Empty, "Invalid verification code.");
                return Page();
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);

            // generate recovery codes
            var codes = await _userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, 10);
            TempData["ModalTitle"] = "Two-factor enabled";
            TempData["ModalBody"] = "Two-factor authentication has been enabled. Store your recovery codes safely.";

            _db.AuditLogs.Add(new Models.AuditLog { UserId = user.Id, Event = "2FA_Enabled", OccurredAt = DateTime.UtcNow, IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString() });
            await _db.SaveChangesAsync();

            return RedirectToPage("/Account/ManageTwoFactor");
        }
    }
}
