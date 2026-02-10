using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Models
{
    public class ApplicationUser : IdentityUser
    {
        [MaxLength(100)]
        public string? FirstName { get; set; }

        [MaxLength(100)]
        public string? LastName { get; set; }

        [MaxLength(50)]
        public string? Gender { get; set; }

        // Encrypted NRIC stored here
        public string? EncryptedNRIC { get; set; }

        public DateTime? DateOfBirth { get; set; }

        public string? ResumeFilePath { get; set; }

        public string? WhoAmI { get; set; }

        public virtual ICollection<PasswordHistory>? PasswordHistories { get; set; }
    }
}