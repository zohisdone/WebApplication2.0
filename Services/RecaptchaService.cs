using Microsoft.Extensions.Configuration;
using System.Net.Http;
using System.Text.Json;

namespace WebApplication1.Services
{
    public class RecaptchaService : IRecaptchaService
    {
        private readonly HttpClient _client;
        private readonly string _secret;
        private readonly double _minScore;

        public RecaptchaService(HttpClient client, IConfiguration config)
        {
            _client = client;
            _secret = config["ReCaptcha:Secret"] ?? string.Empty;
            _minScore = double.TryParse(config["ReCaptcha:MinScore"], out var s) ? s : 0.5;
        }

        public async Task<bool> ValidateTokenAsync(string token)
        {
            if (string.IsNullOrEmpty(_secret) || string.IsNullOrEmpty(token)) return false;
            var resp = await _client.PostAsync($"https://www.google.com/recaptcha/api/siteverify?secret={_secret}&response={token}", null);
            if (!resp.IsSuccessStatusCode) return false;
            using var stream = await resp.Content.ReadAsStreamAsync();
            var doc = await JsonDocument.ParseAsync(stream);
            var root = doc.RootElement;
            var success = root.GetProperty("success").GetBoolean();
            var score = root.TryGetProperty("score", out var sprop) ? sprop.GetDouble() : 0.0;
            return success && score >= _minScore;
        }
    }
}