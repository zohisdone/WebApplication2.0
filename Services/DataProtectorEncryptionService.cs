using Microsoft.AspNetCore.DataProtection;

namespace WebApplication1.Services
{
    public class DataProtectorEncryptionService : IEncryptionService
    {
        private readonly IDataProtector _protector;
        public DataProtectorEncryptionService(IDataProtectionProvider provider)
        {
            _protector = provider.CreateProtector("WebApplication1.NRICProtector.v1");
        }

        public string Protect(string plaintext)
        {
            return _protector.Protect(plaintext);
        }

        public string Unprotect(string protectedText)
        {
            return _protector.Unprotect(protectedText);
        }
    }
}