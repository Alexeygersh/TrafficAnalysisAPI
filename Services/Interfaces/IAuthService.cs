using TrafficAnalysisAPI.Models;

namespace TrafficAnalysisAPI.Services.Interfaces
{
    public interface IAuthService
    {
        Task<User?> GetUserByUsernameAsync(string username);
        Task<User?> GetUserByIdAsync(int userId);
        Task<bool> UserExistsAsync(string username);
        Task<User> CreateUserAsync(string username, string password, string role);
        bool VerifyPassword(string password, string passwordHash);
        string HashPassword(string password);
    }
}

