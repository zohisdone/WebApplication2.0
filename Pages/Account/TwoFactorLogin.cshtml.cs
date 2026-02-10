using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;
using WebApplication1.Models;
using WebApplication1.Data;
using WebApplication1.Services;

namespace WebApplication1.Pages.Account
{
    public class TwoFactorLoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly AuthDbContext _db;
        private readonly UserSessionService _sessionService;

        public TwoFactorLoginModel(SignInManager<ApplicationUser> signInManager, UserManager<ApplicationUser> userManager, AuthDbContext db, UserSessionService sessionService)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _db = db;
            _sessionService = sessionService;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        [BindProperty(SupportsGet = true)]
        public bool RememberMe { get; set; }

        public class InputModel
        {
            [DataType(DataType.Text)]
            public string? Code { get; set; }
            [DataType(DataType.Text)]
            public string? RecoveryCode { get; set; }
            public bool RememberMachine { get; set; }
        }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();

            // Get the two-factor user (the user who initiated the 2FA flow)
            var twoFactorUser = await _signInManager.GetTwoFactorAuthenticationUserAsync();
            if (twoFactorUser == null)
            {
                ModelState.AddModelError(string.Empty, "Unable to load two-factor authentication user.");
                return Page();
            }

            // Attempt authenticator code sign-in for current two-factor user
            var result = await _signInManager.TwoFactorAuthenticatorSignInAsync(Input.Code?.Replace(" ", string.Empty) ?? string.Empty, RememberMe, Input.RememberMachine);
            if (result.Succeeded)
            {
                // create session and re-issue principal with session id
                var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
                var session = await _sessionService.CreateSessionAsync(twoFactorUser.Id, ip);

                await _signInManager.SignOutAsync();
                var principal = await _signInManager.CreateUserPrincipalAsync(twoFactorUser);
                var identity = (System.Security.Claims.ClaimsIdentity)principal.Identity!;
                identity.AddClaim(new System.Security.Claims.Claim("SessionId", session.SessionId));

                await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, principal, new Microsoft.AspNetCore.Authentication.AuthenticationProperties
                {
                    IsPersistent = RememberMe
                });

                _db.AuditLogs.Add(new Models.AuditLog { UserId = twoFactorUser.Id, Event = "2FA_Success", OccurredAt = DateTime.UtcNow, IpAddress = ip });
                await _db.SaveChangesAsync();

                return LocalRedirect("~/");
            }

            if (result.IsLockedOut)
            {
                ModelState.AddModelError(string.Empty, "Account locked out.");
                return Page();
            }

            // Try recovery code
            if (!string.IsNullOrEmpty(Input.RecoveryCode))
            {
                var recResult = await _signInManager.TwoFactorRecoveryCodeSignInAsync(Input.RecoveryCode);
                if (recResult.Succeeded)
                {
                    var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? string.Empty;
                    var session = await _sessionService.CreateSessionAsync(twoFactorUser.Id, ip);

                    await _signInManager.SignOutAsync();
                    var principal = await _signInManager.CreateUserPrincipalAsync(twoFactorUser);
                    var identity = (System.Security.Claims.ClaimsIdentity)principal.Identity!;
                    identity.AddClaim(new System.Security.Claims.Claim("SessionId", session.SessionId));

                    await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, principal, new Microsoft.AspNetCore.Authentication.AuthenticationProperties
                    {
                        IsPersistent = RememberMe
                    });

                    _db.AuditLogs.Add(new Models.AuditLog { UserId = twoFactorUser.Id, Event = "2FA_Recovery_Success", OccurredAt = DateTime.UtcNow, IpAddress = ip });
                    await _db.SaveChangesAsync();

                    return LocalRedirect("~/");
                }
                ModelState.AddModelError(string.Empty, "Invalid recovery code.");
                return Page();
            }

            ModelState.AddModelError(string.Empty, "Invalid authenticator code.");
            return Page();
        }
    }
}
