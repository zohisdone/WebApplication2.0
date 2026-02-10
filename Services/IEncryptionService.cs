namespace WebApplication1.Services
{
    public interface IEncryptionService
    {
        string Protect(string plaintext);
        string Unprotect(string protectedText);
    }
}