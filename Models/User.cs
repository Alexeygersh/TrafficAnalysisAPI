using System.ComponentModel.DataAnnotations;

namespace TrafficAnalysisAPI.Models
{
    // Модель пользователя
    public class User
    {
        [Key]
        public int Id { get; set; }

        [Required]
        [StringLength(50)]
        public string Username { get; set; }

        [Required]
        public string PasswordHash { get; set; }

        [Required]
        [StringLength(20)]
        public string Role { get; set; } // "Admin" или "Analyst"

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}