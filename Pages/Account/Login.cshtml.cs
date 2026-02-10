using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.Authentication;
using System.ComponentModel.DataAnnotations;
using WebApplication1.Data;
using WebApplication1.Models;
using WebApplication1.Services;

namespace WebApplication1.Pages.Account
{
    public class LoginModel : PageModel
    {
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IRecaptchaService _recaptcha;
        private readonly AuthDbContext _db;
        private readonly UserSessionService _sessionService;
        private readonly UserManager<ApplicationUser> _userManager;

        public LoginModel(SignInManager<ApplicationUser> signInManager,
            IRecaptchaService recaptcha,
            AuthDbContext db,
            UserSessionService sessionService,
            UserManager<ApplicationUser> userManager)
        {
            _signInManager = signInManager;
            _recaptcha = recaptcha;
            _db = db;
            _sessionService = sessionService;
            _userManager = userManager;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        public class InputModel
        {
            [Required, EmailAddress]
            public string Email { get; set; } = null!;
            [Required, DataType(DataType.Password)]
            public string Password { get; set; } = null!;
            public bool RememberMe { get; set; }
        }

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync()
        {
            if (!ModelState.IsValid) return Page();

            var user = await _userManager.FindByEmailAsync(Input.Email);
            if (user == null)
            {
                ModelState.AddModelError("", "Invalid login attempt.");
                return Page();
            }

            var result = await _signInManager.PasswordSignInAsync(user, Input.Password, Input.RememberMe, lockoutOnFailure: true);
            if (result.Succeeded)
            {
                var ip = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "";
                var session = await _sessionService.CreateSessionAsync(user.Id, ip);

                // Re-issue principal with session id claim
                await _signInManager.SignOutAsync();
                var principal = await _signInManager.CreateUserPrincipalAsync(user);
                var identity = (System.Security.Claims.ClaimsIdentity)principal.Identity!;
                identity.AddClaim(new System.Security.Claims.Claim("SessionId", session.SessionId));

                await HttpContext.SignInAsync(IdentityConstants.ApplicationScheme, principal, new Microsoft.AspNetCore.Authentication.AuthenticationProperties
                {
                    IsPersistent = Input.RememberMe
                });

                _db.AuditLogs.Add(new AuditLog
                {
                    UserId = user.Id,
                    Event = "Login",
                    IpAddress = ip,
                    OccurredAt = DateTime.UtcNow
                });
                await _db.SaveChangesAsync();

                return LocalRedirect("~/");
            }

            if (result.IsLockedOut)
            {
                ModelState.AddModelError("", "Account locked out. Try again later.");
                _db.AuditLogs.Add(new AuditLog
                {
                    UserId = user.Id,
                    Event = "LockedOut",
                    IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                    OccurredAt = DateTime.UtcNow
                });
                await _db.SaveChangesAsync();
                return Page();
            }

            ModelState.AddModelError("", "Invalid login attempt.");
            _db.AuditLogs.Add(new AuditLog
            {
                UserId = user.Id,
                Event = "FailedLogin",
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                OccurredAt = DateTime.UtcNow
            });
            await _db.SaveChangesAsync();

            return Page();
        }
    }
}
