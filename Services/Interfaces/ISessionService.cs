using TrafficAnalysisAPI.DTOs;

namespace TrafficAnalysisAPI.Services.Interfaces
{
    public interface ISessionService
    {
        Task<IEnumerable<SessionDto>> GetAllSessionsAsync();
        Task<SessionDto?> GetSessionByIdAsync(int id);
        Task<SessionDto> CreateSessionAsync(CreateSessionDto dto);
        Task<bool> UpdateSessionAsync(int id, CreateSessionDto dto);
        Task<bool> DeleteSessionAsync(int id);
        Task<SessionStatisticsDto?> GetSessionStatisticsAsync(int id);
        Task<IEnumerable<PacketDto>> GetAnomalousPacketsAsync(int id);
        Task<bool> CloseSessionAsync(int id);
    }
}