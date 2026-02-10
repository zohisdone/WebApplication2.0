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
            var path = httpContext.Request.Path.Value ?? string.Empty;

            // Never enforce single-session for account management endpoints or static files to avoid interfering with login/register flows
            if (path.StartsWith("/Account", StringComparison.OrdinalIgnoreCase) || path.StartsWith("/lib", StringComparison.OrdinalIgnoreCase) || path.StartsWith("/css", StringComparison.OrdinalIgnoreCase) || path.StartsWith("/js", StringComparison.OrdinalIgnoreCase) || path.StartsWith("/favicon.ico", StringComparison.OrdinalIgnoreCase))
            {
                await _next(httpContext);
                return;
            }

            if (httpContext.User?.Identity?.IsAuthenticated == true)
            {
                var sid = httpContext.User.FindFirst("SessionId")?.Value;
                var uid = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (!string.IsNullOrEmpty(uid) && !string.IsNullOrEmpty(sid))
                {
                    var session = await db.UserSessions.FirstOrDefaultAsync(s => s.UserId == uid && s.SessionId == sid);
                    if (session == null)
                    {
                        // Session invalid — sign out and redirect to login
                        await signInManager.SignOutAsync();
                        httpContext.Response.Redirect("/Account/Login?reason=session_invalid");
                        return;
                    }

                    session.LastActivityAt = DateTime.UtcNow;
                    db.UserSessions.Update(session);
                    await db.SaveChangesAsync();
                }
                // If no session claim present, do not force sign-out here. Allow normal authentication flow.
            }

            await _next(httpContext);
        }
    }
}