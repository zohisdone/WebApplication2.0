using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Models
{
    public class UserSession
    {
        [Key]
        public int Id { get; set; }
        public string UserId { get; set; } = null!;
        public string SessionId { get; set; } = null!;
        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
        public DateTime? LastActivityAt { get; set; } = DateTime.UtcNow;
        public string? IpAddress { get; set; }
    }
}