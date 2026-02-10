using WebApplication1.Data;
using WebApplication1.Models;

namespace WebApplication1.Services
{
    public class UserSessionService
    {
        private readonly AuthDbContext _db;
        public UserSessionService(AuthDbContext db) => _db = db;

        public async Task<UserSession> CreateSessionAsync(string userId, string ip)
        {
            // Remove prior sessions to enforce single session
            var prior = _db.UserSessions.Where(s => s.UserId == userId);
            _db.UserSessions.RemoveRange(prior);

            var session = new UserSession
            {
                UserId = userId,
                SessionId = Guid.NewGuid().ToString("N"),
                CreatedAt = DateTime.UtcNow,
                LastActivityAt = DateTime.UtcNow,
                IpAddress = ip
            };
            _db.UserSessions.Add(session);
            await _db.SaveChangesAsync();
            return session;
        }
    }
}