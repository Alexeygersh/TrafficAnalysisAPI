namespace TrafficAnalysisAPI.Utils
{
    public static class PasswordHasher
    {

        // Хеширует пароль
        public static string HashPassword(string password)
        {
            return BCrypt.Net.BCrypt.HashPassword(password);
        }

        // Проверяет соответствие пароля хешу
        public static bool VerifyPassword(string password, string hash)
        {
            return BCrypt.Net.BCrypt.Verify(password, hash);
        }

        // Проверяет надежность пароля
        public static (bool IsValid, string Message) ValidatePasswordStrength(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                return (false, "Пароль не может быть пустым");

            if (password.Length < 6)
                return (false, "Пароль должен содержать минимум 6 символов");

            if (password.Length > 100)
                return (false, "Пароль слишком длинный (максимум 100 символов)");

            bool hasUpper = password.Any(char.IsUpper);
            bool hasLower = password.Any(char.IsLower);
            bool hasDigit = password.Any(char.IsDigit);
            bool hasSpecial = password.Any(ch => !char.IsLetterOrDigit(ch));

            if (!hasUpper || !hasLower || !hasDigit)
                return (false, "Пароль должен содержать заглавные, строчные буквы и цифры");

            if (!hasSpecial)
                return (false, "Пароль должен содержать специальный символ (!@#$%^&* и т.д.)");

            return (true, "Пароль надежный");
        }
    }
}