using Microsoft.EntityFrameworkCore;
using TrafficAnalysisAPI.Data;
using TrafficAnalysisAPI.DTOs;
using TrafficAnalysisAPI.Models;
using TrafficAnalysisAPI.Services.Interfaces;
using TrafficAnalysisAPI.Utils;

namespace TrafficAnalysisAPI.Services.Implementations
{
    public class AnalysisService : IAnalysisService
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<AnalysisService> _logger;

        public AnalysisService(ApplicationDbContext context, ILogger<AnalysisService> logger)
        {
            _context = context;
            _logger = logger;
        }

        public async Task<IEnumerable<AnalysisDto>> GetAllAnalysesAsync()
        {
            var analyses = await _context.TrafficAnalyses
                .Include(a => a.Packet)
                .OrderByDescending(a => a.DetectedAt)
                .ToListAsync();

            return analyses.Select(MapToDto);
        }

        public async Task<AnalysisDto?> GetAnalysisByIdAsync(int id)
        {
            var analysis = await _context.TrafficAnalyses
                .Include(a => a.Packet)
                .FirstOrDefaultAsync(a => a.Id == id);

            return analysis == null ? null : MapToDto(analysis);
        }

        public async Task<AnalysisDto> CreateAnalysisAsync(CreateAnalysisDto dto)
        {
            // Проверка существования пакета
            var packetExists = await _context.NetworkPackets.AnyAsync(p => p.Id == dto.PacketId);
            if (!packetExists)
                throw new ArgumentException($"Пакет с ID {dto.PacketId} не существует");

            // Проверка на существующий анализ
            var existingAnalysis = await _context.TrafficAnalyses
                .Include(a => a.Packet)
                .FirstOrDefaultAsync(a => a.PacketId == dto.PacketId);

            if (existingAnalysis != null)
            {
                _logger.LogInformation($"Analysis for packet {dto.PacketId} already exists (ID: {existingAnalysis.Id}). Returning existing analysis.");
                return MapToDto(existingAnalysis);
            }

            // Получаем score (потом будет из python)
            double mlScore = dto.MLModelScore ?? await GetMLScoreStub(dto.PacketId);

            var analysis = new TrafficAnalysis
            {
                PacketId = dto.PacketId,
                MLModelScore = mlScore,
                Description = dto.Description,
                DetectedAt = DateTime.UtcNow
            };

            // Автоматическая классификация угрозы
            ClassifyThreat(analysis);

            _context.TrafficAnalyses.Add(analysis);
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Created analysis {analysis.Id} for packet {analysis.PacketId}, threat level: {analysis.ThreatLevel}");

            return await GetAnalysisByIdAsync(analysis.Id)
                ?? throw new InvalidOperationException("Failed to retrieve created analysis");
        }

        public async Task<bool> UpdateAnalysisAsync(int id, CreateAnalysisDto dto)
        {
            var analysis = await _context.TrafficAnalyses.FindAsync(id);
            if (analysis == null) return false;

            analysis.PacketId = dto.PacketId;
            analysis.MLModelScore = dto.MLModelScore ?? analysis.MLModelScore;
            analysis.Description = dto.Description;

            // Перерасчет классификации
            ClassifyThreat(analysis);

            await _context.SaveChangesAsync();
            _logger.LogInformation($"Updated analysis {id}");

            return true;
        }

        public async Task<bool> DeleteAnalysisAsync(int id)
        {
            var analysis = await _context.TrafficAnalyses.FindAsync(id);
            if (analysis == null) return false;

            _context.TrafficAnalyses.Remove(analysis);
            await _context.SaveChangesAsync();

            _logger.LogInformation($"Deleted analysis {id}");
            return true;
        }

        public async Task<AnalysisReportDto?> GetAnalysisReportAsync(int id)
        {
            var analysis = await _context.TrafficAnalyses
                .Include(a => a.Packet)
                .FirstOrDefaultAsync(a => a.Id == id);

            if (analysis == null) return null;

            string reportText = GenerateReport(analysis);

            return new AnalysisReportDto
            {
                AnalysisId = analysis.Id,
                PacketId = analysis.PacketId,
                SourceIP = analysis.Packet.SourceIP,
                DestinationIP = analysis.Packet.DestinationIP,
                Port = analysis.Packet.Port,
                ThreatLevel = analysis.ThreatLevel,
                MLModelScore = analysis.MLModelScore,
                IsMalicious = analysis.IsMalicious,
                DetectedAt = analysis.DetectedAt,
                ReportText = reportText
            };
        }

        public async Task<bool> UpdateConfidenceAsync(int id, double newScore)
        {
            var analysis = await _context.TrafficAnalyses.FindAsync(id);
            if (analysis == null) return false;

            // Усреднение старого и нового скора
            analysis.MLModelScore = (analysis.MLModelScore + newScore) / 2.0;

            // Перерасчет классификации
            ClassifyThreat(analysis);

            await _context.SaveChangesAsync();
            _logger.LogInformation($"Updated confidence for analysis {id}: new ML score = {analysis.MLModelScore:F2}");

            return true;
        }

        // -=--=--=-=--=-=-=-=-=-=-=
        // Заглушка для ML-скора
        // =-=-=-=-=---=-=-=-=-=-=-
        private async Task<double> GetMLScoreStub(int packetId)
        {
            var packet = await _context.NetworkPackets.FindAsync(packetId);

            if (packet == null)
                return 0.5; // Средний риск по умолчанию

            // большие пакеты = выше риск
            double baseScore = 0.3;

            if (packet.PacketSize > 1500)
                baseScore += 0.2;

            if (packet.Protocol == "TCP")
                baseScore += 0.1;

            var random = new Random();
            baseScore += random.NextDouble() * 0.2;

            _logger.LogInformation($"ML Score stub for packet {packetId}: {baseScore:F2}");

            return Math.Min(baseScore, 1.0); // <= 1.0
        }

        // Бизнес-логика: классификация угрозы
        private void ClassifyThreat(TrafficAnalysis analysis)
        {
            if (analysis.MLModelScore >= Constants.CriticalThreshold)
            {
                analysis.ThreatLevel = "Critical";
                analysis.IsMalicious = true;
            }
            else if (analysis.MLModelScore >= Constants.HighThreshold)
            {
                analysis.ThreatLevel = "High";
                analysis.IsMalicious = true;
            }
            else if (analysis.MLModelScore >= Constants.MediumThreshold)
            {
                analysis.ThreatLevel = "Medium";
                analysis.IsMalicious = false;
            }
            else
            {
                analysis.ThreatLevel = "Low";
                analysis.IsMalicious = false;
            }
        }

        // Бизнес-логика: генерация текстового отчета
        private string GenerateReport(TrafficAnalysis analysis)
        {
            var report = $"=== ОТЧЕТ АНАЛИЗА ПАКЕТА #{analysis.PacketId} ===\n\n";
            report += $"ID Анализа: {analysis.Id}\n";
            report += $"Источник: {analysis.Packet.SourceIP}:{analysis.Packet.Port}\n";
            report += $"Назначение: {analysis.Packet.DestinationIP}\n";
            report += $"Протокол: {analysis.Packet.Protocol}\n";
            report += $"Размер пакета: {analysis.Packet.PacketSize} байт\n\n";
            report += $"--- РЕЗУЛЬТАТЫ АНАЛИЗА ---\n";
            report += $"Уровень угрозы: {analysis.ThreatLevel}\n";
            report += $"ML-скор: {analysis.MLModelScore:F2} ({analysis.MLModelScore * 100:F0}%)\n";
            report += $"Статус: {(analysis.IsMalicious ? "❌ ВРЕДОНОСНЫЙ" : "✅ БЕЗОПАСНЫЙ")}\n";
            report += $"Дата обнаружения: {analysis.DetectedAt:yyyy-MM-dd HH:mm:ss} UTC\n";

            if (!string.IsNullOrEmpty(analysis.Description))
                report += $"\nОписание: {analysis.Description}\n";

            report += "\n=== КОНЕЦ ОТЧЕТА ===";

            return report;
        }

        // Маппинг Entity -> DTO
        private AnalysisDto MapToDto(TrafficAnalysis analysis)
        {
            return new AnalysisDto
            {
                Id = analysis.Id,
                PacketId = analysis.PacketId,
                ThreatLevel = analysis.ThreatLevel,
                IsMalicious = analysis.IsMalicious,
                MLModelScore = analysis.MLModelScore,
                DetectedAt = analysis.DetectedAt,
                Description = analysis.Description
            };
        }
    }
}