using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TrafficAnalysisAPI.Data;

namespace TrafficAnalysisAPI.Controllers
{
    /// <summary>
    /// Временный shim — пока фронтенд использует /api/clustering/sessions.
    /// В финальной чистке перенести этот endpoint в SessionsController.
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    [Authorize(Policy = "AuthorizedUser")]
    public class ClusteringController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public ClusteringController(ApplicationDbContext context)
        {
            _context = context;
        }

        [HttpGet("sessions")]
        public async Task<ActionResult<List<SessionFilterDto>>> GetSessions()
        {
            var sessions = await _context.TrafficSessions
                .Select(s => new SessionFilterDto
                {
                    Id = s.Id,
                    SessionName = s.SessionName,
                    PacketCount = _context.NetworkPackets.Count(p => p.SessionId == s.Id),
                    FlowCount = _context.FlowMetrics.Count(f => f.SessionId == s.Id),
                })
                .OrderByDescending(s => s.Id)
                .ToListAsync();

            return Ok(sessions);
        }

        public class SessionFilterDto
        {
            public int Id { get; set; }
            public string SessionName { get; set; } = "";
            public int PacketCount { get; set; }
            public int FlowCount { get; set; }
        }
    }
}