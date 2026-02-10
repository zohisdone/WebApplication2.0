using Microsoft.Extensions.Configuration;
using System.Net;
using System.Net.Mail;

namespace WebApplication1.Services
{
    public class SmtpEmailSender : IEmailSender
    {
        private readonly IConfiguration _config;
        private readonly SmtpSettings _settings;

        public SmtpEmailSender(IConfiguration config)
        {
            _config = config;
            _settings = new SmtpSettings();
            config.GetSection("Smtp").Bind(_settings);
        }

        public async Task SendEmailAsync(string toEmail, string subject, string htmlMessage)
        {
            using var smtp = new SmtpClient(_settings.Host, _settings.Port)
            {
                EnableSsl = _settings.EnableSsl,
                Credentials = new NetworkCredential(_settings.Username, _settings.Password)
            };

            var mail = new MailMessage
            {
                From = new MailAddress(_settings.From, _settings.FromDisplayName),
                Subject = subject,
                Body = htmlMessage,
                IsBodyHtml = true
            };
            mail.To.Add(toEmail);

            await smtp.SendMailAsync(mail);
        }

        private class SmtpSettings
        {
            public string Host { get; set; } = "smtp.example.com";
            public int Port { get; set; } = 587;
            public bool EnableSsl { get; set; } = true;
            public string Username { get; set; } = "";
            public string Password { get; set; } = "";
            public string From { get; set; } = "no-reply@acejobagency.com";
            public string FromDisplayName { get; set; } = "Ace Job Agency";
        }
    }
}