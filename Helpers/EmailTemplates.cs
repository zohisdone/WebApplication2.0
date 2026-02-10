namespace WebApplication1.Helpers
{
    public static class EmailTemplates
    {
        public const string ResetPasswordHtmlTemplate = @"<!doctype html>
<html>
<head>
  <meta charset=""utf-8"" />
  <title>Ace Job Agency - Password reset</title>
  <style>body{font-family:Arial,sans-serif;color:#333}.container{max-width:600px;margin:0 auto;padding:20px}.btn{display:inline-block;padding:10px 16px;background:#007bff;color:white;text-decoration:none;border-radius:4px}</style>
</head>
<body>
  <div class=""container"">
    <p>Hello {{DisplayName}},</p>
    <p>You requested to reset your Ace Job Agency account password. Click the button below to reset it. The link will expire according to the application's policy.</p>
    <p><a class=""btn"" href=""{{CallbackUrl}}"">Reset your password</a></p>
    <p>If the button doesn't work, copy and paste this URL into your browser:</p>
    <p><a href=""{{CallbackUrl}}"">{{CallbackUrl}}</a></p>
    <hr />
    <p>If you did not request this, ignore this email or contact support at {{SupportEmail}}.</p>
  </div>
</body>
</html>";
    }
}