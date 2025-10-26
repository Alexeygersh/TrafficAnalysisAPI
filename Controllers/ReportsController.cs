using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TrafficAnalysisAPI.DTOs;
using TrafficAnalysisAPI.Services.Interfaces;

namespace TrafficAnalysisAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Policy = "AuthorizedUser")]
    public class ReportsController : ControllerBase
    {
        private readonly IReportService _reportService;
        private readonly ILogger<ReportsController> _logger;

        public ReportsController(IReportService reportService, ILogger<ReportsController> logger)
        {
            _reportService = reportService;
            _logger = logger;
        }

        // LINQ запрос 1: Все подозрительные пакеты с результатами анализа
        [HttpGet("suspicious-packets")]
        [ProducesResponseType(typeof(IEnumerable<SuspiciousPacketDto>), StatusCodes.Status200OK)]
        public async Task<ActionResult<IEnumerable<SuspiciousPacketDto>>> GetSuspiciousPackets()
        {
            var packets = await _reportService.GetSuspiciousPacketsAsync();
            return Ok(packets);
        }

        // LINQ запрос 2: Статистика угроз по протоколам
        [HttpGet("threats-by-protocol")]
        [ProducesResponseType(typeof(IEnumerable<ThreatsByProtocolDto>), StatusCodes.Status200OK)]
        public async Task<ActionResult<IEnumerable<ThreatsByProtocolDto>>> GetThreatsByProtocol()
        {
            var threats = await _reportService.GetThreatsByProtocolAsync();
            return Ok(threats);
        }

        // LINQ запрос 3: Топ вредоносных IP-адресов
        [HttpGet("top-malicious-ips")]
        [ProducesResponseType(typeof(IEnumerable<TopMaliciousIPDto>), StatusCodes.Status200OK)]
        public async Task<ActionResult<IEnumerable<TopMaliciousIPDto>>> GetTopMaliciousIPs([FromQuery] int top = 10)
        {
            var ips = await _reportService.GetTopMaliciousIPsAsync(top);
            return Ok(ips);
        }

        // LINQ запрос 4: История анализа для конкретного источника
        [HttpGet("source-history/{sourceIP}")]
        [ProducesResponseType(typeof(SourceHistoryDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<SourceHistoryDto>> GetSourceHistory(string sourceIP)
        {
            var history = await _reportService.GetSourceHistoryAsync(sourceIP);

            if (history == null)
                return NotFound(new { message = "Пакеты от данного источника не найдены" });

            return Ok(history);
        }

        // LINQ запрос 5: Сводный отчет по временным интервалам
        [HttpGet("time-based-summary")]
        [ProducesResponseType(typeof(TimeBasedSummaryDto), StatusCodes.Status200OK)]
        public async Task<ActionResult<TimeBasedSummaryDto>> GetTimeBasedSummary([FromQuery] int hours = 24)
        {
            var summary = await _reportService.GetTimeBasedSummaryAsync(hours);
            return Ok(summary);
        }

        // LINQ запрос 6: Детальный отчет по сессии
        [HttpGet("session-detailed/{sessionId}")]
        [ProducesResponseType(typeof(SessionStatisticsDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<SessionStatisticsDto>> GetSessionDetailedReport(int sessionId)
        {
            var report = await _reportService.GetSessionDetailedReportAsync(sessionId);

            if (report == null)
                return NotFound(new { message = "Сессия не найдена" });

            return Ok(report);
        }
    }
}