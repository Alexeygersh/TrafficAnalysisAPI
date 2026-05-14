using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TrafficAnalysisAPI.DTOs;
using TrafficAnalysisAPI.Services.Interfaces;

namespace TrafficAnalysisAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SessionsController : ControllerBase
    {
        private readonly ISessionService _sessionService;
        private readonly ILogger<SessionsController> _logger;

        public SessionsController(ISessionService sessionService, ILogger<SessionsController> logger)
        {
            _sessionService = sessionService;
            _logger = logger;
        }

        [HttpGet]
        [Authorize(Policy = "AuthorizedUser")]
        [ProducesResponseType(typeof(IEnumerable<SessionDto>), StatusCodes.Status200OK)]
        public async Task<ActionResult<IEnumerable<SessionDto>>> GetSessions()
        {
            var sessions = await _sessionService.GetAllSessionsAsync();
            return Ok(sessions);
        }

        [HttpGet("{id}")]
        [Authorize(Policy = "AuthorizedUser")]
        [ProducesResponseType(typeof(SessionDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<SessionDto>> GetSession(int id)
        {
            var session = await _sessionService.GetSessionByIdAsync(id);

            if (session == null)
                return NotFound(new { message = $"Сессия с ID {id} не найдена" });

            return Ok(session);
        }

        [HttpPost]
        [Authorize(Policy = "AdminOnly")]
        [ProducesResponseType(typeof(SessionDto), StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<SessionDto>> CreateSession([FromBody] CreateSessionDto dto)
        {
            try
            {
                var session = await _sessionService.CreateSessionAsync(dto);
                return CreatedAtAction(nameof(GetSession), new { id = session.Id }, session);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating session");
                return BadRequest(new { message = "Ошибка при создании сессии" });
            }
        }

        [HttpPut("{id}")]
        [Authorize(Policy = "AdminOnly")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> UpdateSession(int id, [FromBody] CreateSessionDto dto)
        {
            var success = await _sessionService.UpdateSessionAsync(id, dto);

            if (!success)
                return NotFound(new { message = $"Сессия с ID {id} не найдена" });

            return NoContent();
        }

        [HttpDelete("{id}")]
        [Authorize(Policy = "AdminOnly")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> DeleteSession(int id)
        {
            var success = await _sessionService.DeleteSessionAsync(id);

            if (!success)
                return NotFound(new { message = $"Сессия с ID {id} не найдена" });

            return NoContent();
        }

        [HttpGet("statistics/{id}")]
        [Authorize(Policy = "AuthorizedUser")]
        [ProducesResponseType(typeof(SessionStatisticsDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<SessionStatisticsDto>> GetStatistics(int id)
        {
            var stats = await _sessionService.GetSessionStatisticsAsync(id);

            if (stats == null)
                return NotFound(new { message = $"Сессия с ID {id} не найдена" });

            return Ok(stats);
        }

        [HttpGet("anomalous-packets/{id}")]
        [Authorize(Policy = "AuthorizedUser")]
        [ProducesResponseType(typeof(IEnumerable<PacketDto>), StatusCodes.Status200OK)]
        public async Task<ActionResult<IEnumerable<PacketDto>>> GetAnomalousPackets(int id)
        {
            var packets = await _sessionService.GetAnomalousPacketsAsync(id);
            return Ok(packets);
        }

        [HttpPost("close/{id}")]
        [Authorize(Policy = "AdminOnly")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> CloseSession(int id)
        {
            try
            {
                var success = await _sessionService.CloseSessionAsync(id);

                if (!success)
                    return NotFound(new { message = $"Сессия с ID {id} не найдена" });

                return Ok(new { message = "Сессия успешно завершена" });
            }
            catch (InvalidOperationException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
        }
    }
}