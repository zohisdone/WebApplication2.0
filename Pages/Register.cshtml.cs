using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using WebApplication1.Models;
using WebApplication1.Data;
using WebApplication1.Services;
using System.Text.RegularExpressions;

namespace WebApplication1.Pages
{
    public class RegisterModel : PageModel
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEncryptionService _encryption;
        private readonly IWebHostEnvironment _env;
        private readonly AuthDbContext _db;
        private readonly IRecaptchaService _recaptcha;
        private readonly IPasswordHasher<ApplicationUser> _passwordHasher;

        public RegisterModel(UserManager<ApplicationUser> userManager,
            SignInManager<ApplicationUser> signInManager,
            IEncryptionService encryption,
            IWebHostEnvironment env,
            AuthDbContext db,
            IRecaptchaService recaptcha,
            IPasswordHasher<ApplicationUser> passwordHasher)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _encryption = encryption;
            _env = env;
            _db = db;
            _recaptcha = recaptcha;
            _passwordHasher = passwordHasher;
        }

        [BindProperty]
        public InputModel Input { get; set; } = new();

        [BindProperty]
        public IFormFile? Resume { get; set; }

        [BindProperty]
        public string? RecaptchaToken { get; set; }

        public class InputModel
        {
            [Required, StringLength(100)]
            public string FirstName { get; set; } = null!;

            [Required, StringLength(100)]
            public string LastName { get; set; } = null!;

            public string? Gender { get; set; }

            [Required]
            public string NRIC { get; set; } = null!;

            [Required, EmailAddress]
            public string Email { get; set; } = null!;

            [Required, DataType(DataType.Password)]
            [StringLength(100, MinimumLength = 12)]
            public string Password { get; set; } = null!;

            [Required, DataType(DataType.Password), Compare(nameof(Password))]
            public string ConfirmPassword { get; set; } = null!;

            [DataType(DataType.Date)]
            public DateTime? DateOfBirth { get; set; }

            public string? WhoAmI { get; set; }
        }

        private static readonly Regex PasswordRegex = new(@"^(?=.{12,}$)(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*\W).*$");

        public void OnGet()
        {
        }

        public async Task<IActionResult> OnPostAsync(IFormFile resume)
        {
            Resume = resume;

            // Validate reCAPTCHA
            if (!await _recaptcha.ValidateTokenAsync(RecaptchaToken ?? string.Empty))
            {
                ModelState.AddModelError("", "reCAPTCHA validation failed.");
                return Page();
            }

            if (!ModelState.IsValid) return Page();

            // Resume validation
            if (Resume == null)
            {
                ModelState.AddModelError("Resume", "Resume is required (.docx or .pdf).");
                return Page();
            }
            var allowed = new[] { ".pdf", ".docx" };
            var ext = Path.GetExtension(Resume.FileName).ToLowerInvariant();
            if (!allowed.Contains(ext))
            {
                ModelState.AddModelError("Resume", "Allowed file types: .pdf, .docx");
                return Page();
            }
            if (Resume.Length > 5 * 1024 * 1024)
            {
                ModelState.AddModelError("Resume", "Max resume size is 5 MB");
                return Page();
            }

            // Password regex check
            if (!PasswordRegex.IsMatch(Input.Password))
            {
                ModelState.AddModelError("Input.Password", "Password must be at least 12 characters and include uppercase, lowercase, number and special character.");
                return Page();
            }

            // Check unique email
            var existing = await _userManager.FindByEmailAsync(Input.Email);
            if (existing != null)
            {
                ModelState.AddModelError("Input.Email", "Email already taken.");
                return Page();
            }

            var user = new ApplicationUser
            {
                UserName = Input.Email,
                Email = Input.Email,
                FirstName = Input.FirstName,
                LastName = Input.LastName,
                Gender = Input.Gender,
                DateOfBirth = Input.DateOfBirth,
                WhoAmI = Input.WhoAmI
            };

            // Encrypt NRIC
            user.EncryptedNRIC = _encryption.Protect(Input.NRIC);

            // Save resume
            var uploads = Path.Combine(_env.WebRootPath ?? Path.Combine(Directory.GetCurrentDirectory(), "wwwroot"), "uploads");
            Directory.CreateDirectory(uploads);
            var filename = $"{Guid.NewGuid():N}{ext}";
            var filepath = Path.Combine(uploads, filename);
            using (var fs = System.IO.File.Create(filepath))
            {
                await Resume.CopyToAsync(fs);
            }
            user.ResumeFilePath = $"/uploads/{filename}";

            var result = await _userManager.CreateAsync(user, Input.Password);
            if (!result.Succeeded)
            {
                foreach (var err in result.Errors)
                    ModelState.AddModelError("", err.Description);
                return Page();
            }

            // Store password history
            var ph = new PasswordHistory
            {
                UserId = user.Id,
                HashedPassword = _passwordHasher.HashPassword(user, Input.Password)
            };
            _db.PasswordHistories.Add(ph);
            await _db.SaveChangesAsync();

            // Auto-login
            await _signInManager.SignInAsync(user, isPersistent: false);

            // Audit
            _db.AuditLogs.Add(new AuditLog
            {
                UserId = user.Id,
                Event = "RegisterAndLogin",
                IpAddress = HttpContext.Connection.RemoteIpAddress?.ToString(),
                OccurredAt = DateTime.UtcNow
            });
            await _db.SaveChangesAsync();

            return LocalRedirect("~/");
        }
    }
}
