using TrafficAnalysisAPI.DTOs;

namespace TrafficAnalysisAPI.Services.Interfaces
{
    public interface IReportService
    {
        Task<IEnumerable<SuspiciousPacketDto>> GetSuspiciousPacketsAsync();
        Task<IEnumerable<ThreatsByProtocolDto>> GetThreatsByProtocolAsync();
        Task<IEnumerable<TopMaliciousIPDto>> GetTopMaliciousIPsAsync(int top = 10);
        Task<SourceHistoryDto?> GetSourceHistoryAsync(string sourceIP);
        Task<TimeBasedSummaryDto> GetTimeBasedSummaryAsync(int hours = 24);
        Task<SessionStatisticsDto?> GetSessionDetailedReportAsync(int sessionId);
    }
}