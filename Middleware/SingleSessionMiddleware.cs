using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using WebApplication1.Data;
using WebApplication1.Models;

namespace WebApplication1.Middleware
{
    public class SingleSessionMiddleware
    {
        private readonly RequestDelegate _next;

        public SingleSessionMiddleware(RequestDelegate next)
        {
            _next = next;
        }

        public async Task InvokeAsync(HttpContext httpContext, AuthDbContext db, UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager)
        {
            if (httpContext.User?.Identity?.IsAuthenticated == true)
            {
                var sid = httpContext.User.FindFirst("SessionId")?.Value;
                var uid = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (!string.IsNullOrEmpty(uid))
                {
                    var session = await db.UserSessions.FirstOrDefaultAsync(s => s.UserId == uid && s.SessionId == sid);
                    if (session == null)
                    {
                        // Session invalid — sign out
                        await signInManager.SignOutAsync();
                        httpContext.Response.Redirect("/Account/Login?reason=session_invalid");
                        return;
                    }
                    session.LastActivityAt = DateTime.UtcNow;
                    await db.SaveChangesAsync();
                }
            }

            await _next(httpContext);
        }
    }
}