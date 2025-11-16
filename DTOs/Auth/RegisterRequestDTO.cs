using System.ComponentModel.DataAnnotations;

namespace TrafficAnalysisAPI.DTOs.Auth
{
    public class RegisterRequestDto
    {
        [Required(ErrorMessage = "Логин обязателен")]
        [MinLength(3, ErrorMessage = "Логин должен быть минимум 3 символа")]
        [MaxLength(50, ErrorMessage = "Логин должен быть максимум 50 символов")]
        public string Username { get; set; } = string.Empty;

        [Required(ErrorMessage = "Пароль обязателен")]
        [MinLength(6, ErrorMessage = "Пароль должен быть минимум 6 символов")]
        public string Password { get; set; } = string.Empty;

        [Required(ErrorMessage = "Роль обязательна")]
        [RegularExpression("^(Admin|Analyst)$", ErrorMessage = "Роль должна быть Admin или Analyst")]
        public string Role { get; set; } = string.Empty;
    }
}