using System.ComponentModel.DataAnnotations;

namespace WebApplication1.Models
{
    public class AuditLog
    {
        [Key]
        public int Id { get; set; }
        public string? UserId { get; set; }
        public string Event { get; set; } = null!; // e.g., Login, Logout
        public DateTime OccurredAt { get; set; } = DateTime.UtcNow;
        public string? IpAddress { get; set; }
        public string? Details { get; set; }
    }
}