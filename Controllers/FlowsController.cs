using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TrafficAnalysisAPI.Data;
using TrafficAnalysisAPI.Models;

namespace TrafficAnalysisAPI.Controllers
{
    /// <summary>
    /// Endpoint для получения данных одного потока (flow) и его пакетов.
    /// Используется страницей flow-detail на фронтенде.
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    // [Authorize(Policy = "AuthorizedUser")]
    public class FlowsController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly ILogger<FlowsController> _logger;

        public FlowsController(
            ApplicationDbContext context,
            ILogger<FlowsController> logger)
        {
            _context = context;
            _logger = logger;
        }

        /// <summary>
        /// GET /api/flows/{id}
        /// Полные данные одного flow с привязанными метриками.
        /// </summary>
        [HttpGet("{id:int}")]
        [ProducesResponseType(typeof(FlowMetrics), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<FlowMetrics>> GetFlow(int id)
        {
            var flow = await _context.FlowMetrics
                .AsNoTracking()
                .Include(f => f.Session)
                .FirstOrDefaultAsync(f => f.Id == id);

            if (flow == null)
                return NotFound(new { message = $"Flow #{id} не найден" });

            return Ok(flow);
        }

        /// <summary>
        /// GET /api/flows/{id}/packets
        /// Пакеты которые входят в этот flow (через FlowId связь).
        /// </summary>
        [HttpGet("{id:int}/packets")]
        [ProducesResponseType(typeof(List<NetworkPacket>), StatusCodes.Status200OK)]
        public async Task<ActionResult<List<NetworkPacket>>> GetFlowPackets(int id)
        {
            // Проверка что flow существует
            var exists = await _context.FlowMetrics.AnyAsync(f => f.Id == id);
            if (!exists)
                return NotFound(new { message = $"Flow #{id} не найден" });

            var packets = await _context.NetworkPackets
                .AsNoTracking()
                .Where(p => p.FlowId == id)
                .OrderBy(p => p.Timestamp)
                .ToListAsync();

            return Ok(packets);
        }

        /// <summary>
        /// GET /api/flows/by-session/{sessionId}
        /// Все flows одной сессии (компактный список — для табличного отображения).
        /// </summary>
        [HttpGet("by-session/{sessionId:int}")]
        public async Task<ActionResult<List<FlowSummaryDto>>> GetFlowsBySession(int sessionId)
        {
            var flows = await _context.FlowMetrics
                .AsNoTracking()
                .Where(f => f.SessionId == sessionId)
                .OrderBy(f => f.Id)
                .Select(f => new FlowSummaryDto
                {
                    Id = f.Id,
                    SourceIP = f.SourceIP,
                    DestinationIP = f.DestinationIP,
                    SourcePort = f.SourcePort,
                    DestinationPort = f.DestinationPort,
                    Protocol = f.Protocol,
                    FlowDuration = f.FlowDuration,
                    TotalPackets = f.TotalFwdPackets + f.TotalBackwardPackets,
                    ThreatScore = f.ThreatScore,
                    ThreatLevel = f.ThreatLevel,
                    PredictedBy = f.PredictedBy,
                })
                .ToListAsync();

            return Ok(flows);
        }

        /// <summary>
        /// Лёгкий DTO для списка flows. Без всех 78 признаков.
        /// </summary>
        public class FlowSummaryDto
        {
            public int Id { get; set; }
            public string SourceIP { get; set; } = "";
            public string DestinationIP { get; set; } = "";
            public int SourcePort { get; set; }
            public int DestinationPort { get; set; }
            public string Protocol { get; set; } = "";
            public double FlowDuration { get; set; }
            public int TotalPackets { get; set; }
            public double? ThreatScore { get; set; }
            public string? ThreatLevel { get; set; }
            public string? PredictedBy { get; set; }
        }
    }
}
