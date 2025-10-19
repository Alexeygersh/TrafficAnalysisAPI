using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TrafficAnalysisAPI.Data;
using TrafficAnalysisAPI.Models;

namespace TrafficAnalysisAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SessionsController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public SessionsController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: api/Sessions
        [HttpGet]
        [Authorize(Policy = "AuthorizedUser")]
        public async Task<ActionResult<IEnumerable<TrafficSession>>> GetSessions()
        {
            return await _context.TrafficSessions
                .Include(s => s.Packets)
                .ToListAsync();
        }

        // GET: api/Sessions/5
        [HttpGet("{id}")]
        [Authorize(Policy = "AuthorizedUser")]
        public async Task<ActionResult<TrafficSession>> GetSession(int id)
        {
            var session = await _context.TrafficSessions
                .Include(s => s.Packets)
                .FirstOrDefaultAsync(s => s.Id == id);

            if (session == null)
                return NotFound();

            return session;
        }

        // POST: api/Sessions
        [HttpPost]
        [Authorize(Policy = "AdminOnly")]
        public async Task<ActionResult<TrafficSession>> CreateSession(TrafficSession session)
        {
            _context.TrafficSessions.Add(session);
            await _context.SaveChangesAsync();

            return CreatedAtAction(nameof(GetSession), new { id = session.Id }, session);
        }

        // PUT: api/Sessions/5
        [HttpPut("{id}")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> UpdateSession(int id, TrafficSession session)
        {
            if (id != session.Id)
                return BadRequest();

            _context.Entry(session).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!SessionExists(id))
                    return NotFound();
                throw;
            }

            return NoContent();
        }

        // DELETE: api/Sessions/5
        [HttpDelete("{id}")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> DeleteSession(int id)
        {
            var session = await _context.TrafficSessions.FindAsync(id);
            if (session == null)
                return NotFound();

            _context.TrafficSessions.Remove(session);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        // GET: api/Sessions/statistics/5
        [HttpGet("statistics/{id}")]
        [Authorize(Policy = "AuthorizedUser")]
        public async Task<ActionResult<Dictionary<string, object>>> GetStatistics(int id)
        {
            var session = await _context.TrafficSessions
                .Include(s => s.Packets)
                .FirstOrDefaultAsync(s => s.Id == id);

            if (session == null)
                return NotFound();

            return Ok(session.CalculateStatistics());
        }

        // GET: api/Sessions/anomalous-packets/5
        [HttpGet("anomalous-packets/{id}")]
        [Authorize(Policy = "AuthorizedUser")]
        public async Task<ActionResult<IEnumerable<NetworkPacket>>> GetAnomalousPackets(int id)
        {
            var session = await _context.TrafficSessions
                .Include(s => s.Packets)
                .FirstOrDefaultAsync(s => s.Id == id);

            if (session == null)
                return NotFound();

            return Ok(session.GetAnomalousPackets());
        }

        // POST: api/Sessions/close/5
        [HttpPost("close/{id}")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> CloseSession(int id)
        {
            var session = await _context.TrafficSessions.FindAsync(id);
            if (session == null)
                return NotFound();

            if (session.EndTime.HasValue)
                return BadRequest(new { message = "Сессия уже завершена" });

            session.EndTime = DateTime.UtcNow;
            await _context.SaveChangesAsync();

            return Ok(new { message = "Сессия успешно завершена" });
        }

        private bool SessionExists(int id)
        {
            return _context.TrafficSessions.Any(e => e.Id == id);
        }
    }
}