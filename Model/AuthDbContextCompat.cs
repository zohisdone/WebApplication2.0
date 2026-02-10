using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;

namespace WebApplication1.Model
{
    // Backwards-compatible type used by generated migrations which reference WebApplication1.Model.AuthDbContext.
    // This class simply derives from the new AuthDbContext implementation in WebApplication1.Data
    public class AuthDbContext : WebApplication1.Data.AuthDbContext
    {
        public AuthDbContext(DbContextOptions<WebApplication1.Data.AuthDbContext> options, IConfiguration configuration)
            : base(options, configuration)
        {
        }
    }
}
