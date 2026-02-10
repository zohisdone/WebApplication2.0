using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Models
{
    public class PasswordHistory
    {
        [Key]
        public int Id { get; set; }
        public string UserId { get; set; } = null!;
        public string HashedPassword { get; set; } = null!;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public virtual ApplicationUser? User { get; set; }
    }
}