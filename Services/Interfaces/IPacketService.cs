using TrafficAnalysisAPI.DTOs;

namespace TrafficAnalysisAPI.Services.Interfaces
{
    public interface IPacketService
    {
        Task<IEnumerable<PacketDto>> GetAllPacketsAsync();
        Task<PacketDto?> GetPacketByIdAsync(int id);
        Task<PacketDto> CreatePacketAsync(CreatePacketDto dto);
        Task<bool> UpdatePacketAsync(int id, UpdatePacketDto dto);
        Task<bool> DeletePacketAsync(int id);
        Task<ThreatScoreDto?> GetThreatScoreAsync(int id);
    }
}