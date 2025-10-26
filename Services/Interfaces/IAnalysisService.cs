using TrafficAnalysisAPI.DTOs;

namespace TrafficAnalysisAPI.Services.Interfaces
{
    public interface IAnalysisService
    {
        Task<IEnumerable<AnalysisDto>> GetAllAnalysesAsync();
        Task<AnalysisDto?> GetAnalysisByIdAsync(int id);
        Task<AnalysisDto> CreateAnalysisAsync(CreateAnalysisDto dto);
        Task<bool> UpdateAnalysisAsync(int id, CreateAnalysisDto dto);
        Task<bool> DeleteAnalysisAsync(int id);
        Task<AnalysisReportDto?> GetAnalysisReportAsync(int id);
        Task<bool> UpdateConfidenceAsync(int id, double newScore);
    }
}