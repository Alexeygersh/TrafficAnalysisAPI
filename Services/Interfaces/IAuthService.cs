using TrafficAnalysisAPI.Models;

namespace TrafficAnalysisAPI.Services.Interfaces
{
    public interface IAuthService
    {
        Task<User?> GetUserByUsernameAsync(string username);
        Task<User?> GetUserByIdAsync(int userId);
        Task<IEnumerable<User>> GetAllUsersAsync();
        Task<bool> UserExistsAsync(string username);
        Task<User> CreateUserAsync(string username, string password, string role);
        Task<bool> DeleteUserAsync(int userId);
        bool VerifyPassword(string password, string passwordHash);
        string HashPassword(string password);
    }
}

