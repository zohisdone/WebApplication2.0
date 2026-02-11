using System.ComponentModel.DataAnnotations;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using WebApplication1.Models;
using WebApplication1.Data;
using WebApplication1.Services;
using Microsoft.EntityFrameworkCore;

namespace WebApplication1.Pages.Account
{
    public class ForgotPasswordModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailSender _emailSender;
        private readonly AuthDbContext _db;
        private readonly IRecaptchaService _recaptcha;
        private readonly ILogger<ForgotPasswordModel> _logger;
        private readonly HtmlEncoder _htmlEncoder;

        public ForgotPasswordModel(
            UserManager<ApplicationUser> userManager,
            IEmailSender emailSender,
            AuthDbContext db,
            IRecaptchaService recaptcha,
            ILogger<ForgotPasswordModel> logger,
            HtmlEncoder htmlEncoder)
        {
            _userManager = userManager;
            _emailSender = emailSender;
            _db = db;
            _recaptcha = recaptcha;
            _logger = logger;
            _htmlEncoder = htmlEncoder;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        [BindProperty]
        public string? RecaptchaToken { get; set; }

        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; } = null!;
        }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid)
            {
                return Page();
            }

            var email = Input.Email?.Trim() ?? string.Empty;
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            // Validate reCAPTCHA server-side
            if (!await _recaptcha.ValidateTokenAsync(RecaptchaToken ?? string.Empty))
            {
                ModelState.AddModelError(string.Empty, "reCAPTCHA validation failed. Please try again.");
                return Page();
            }

            // Log the request attempt for monitoring (generic)
            try
            {
                _db.AuditLogs.Add(new AuditLog
                {
                    UserId = string.Empty,
                    Event = "PasswordResetRequested",
                    IpAddress = ip,
                    Details = null,
                    OccurredAt = DateTime.UtcNow
                });
                await _db.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to write audit log for password reset request");
            }

            // Optional rate-limiting
            var cutoff = DateTime.UtcNow.AddMinutes(-15);
            var perIpCount = await _db.AuditLogs
                .Where(a => a.Event == "PasswordResetRequested" && a.IpAddress == ip && a.OccurredAt >= cutoff)
                .CountAsync();

            if (perIpCount > 50)
            {
                _logger.LogWarning("Rate-limiting triggered for password reset from ip={Ip}", ip);

                try
                {
                    _db.AuditLogs.Add(new AuditLog
                    {
                        UserId = string.Empty,
                        Event = "PasswordResetRateLimited",
                        IpAddress = ip,
                        Details = null,
                        OccurredAt = DateTime.UtcNow
                    });
                    await _db.SaveChangesAsync();
                }
                catch
                {
                }

                TempData["StatusMessage"] = "If an account with that email exists, a password reset link has been sent.";
                return RedirectToPage("/Account/Login");
            }

            var user = await _userManager.FindByEmailAsync(email);
            if (user != null && await _userManager.IsEmailConfirmedAsync(user))
            {
                try
                {
                    var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                    var callbackUrl = Url.Page(
                        "/Account/ResetPassword",
                        pageHandler: null,
                        values: new { email = user.Email, token = token },
                        protocol: Request.Scheme);

                    var subject = "Ace Job Agency - Reset your password";
                    var htmlBody = WebApplication1.Helpers.EmailTemplates.ResetPasswordHtmlTemplate
                        .Replace("{{DisplayName}}", _htmlEncoder.Encode($"{user.FirstName} {user.LastName}".Trim()))
                        .Replace("{{CallbackUrl}}", _htmlEncoder.Encode(callbackUrl))
                        .Replace("{{SupportEmail}}", _htmlEncoder.Encode("support@acejobagency.com"));

                    await _emailSender.SendEmailAsync(user.Email, subject, htmlBody);

                    _db.AuditLogs.Add(new AuditLog
                    {
                        UserId = user.Id,
                        Event = "PasswordResetEmailSent",
                        IpAddress = ip,
                        Details = null,
                        OccurredAt = DateTime.UtcNow
                    });
                    await _db.SaveChangesAsync();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to generate/send password reset email");
                }
            }
            else
            {
                _logger.LogInformation("Password reset requested (generic outcome)");
            }

            TempData["StatusMessage"] = "If an account with that email exists, a password reset link has been sent.";
            return RedirectToPage("/Account/Login");
        }
    }
}
