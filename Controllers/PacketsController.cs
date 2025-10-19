using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TrafficAnalysisAPI.Data;
using TrafficAnalysisAPI.Models;

namespace TrafficAnalysisAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PacketsController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public PacketsController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: api/Packets - получить все пакеты
        [HttpGet]
        [Authorize(Policy = "AuthorizedUser")]
        public async Task<ActionResult<IEnumerable<NetworkPacket>>> GetPackets()
        {
            return await _context.NetworkPackets
                .Include(p => p.Session)
                .Include(p => p.Analysis)
                .ToListAsync();
        }

        // GET: api/Packets/5 - получить пакет по ID
        [HttpGet("{id}")]
        [Authorize(Policy = "AuthorizedUser")]
        public async Task<ActionResult<NetworkPacket>> GetPacket(int id)
        {
            var packet = await _context.NetworkPackets
                .Include(p => p.Session)
                .Include(p => p.Analysis)
                .FirstOrDefaultAsync(p => p.Id == id);

            if (packet == null)
                return NotFound();

            return packet;
        }

        // POST: api/Packets - создать новый пакет (только для админов)
        [HttpPost]
        [Authorize(Policy = "AdminOnly")]
        public async Task<ActionResult<NetworkPacket>> CreatePacket(NetworkPacket packet)
        {
            _context.NetworkPackets.Add(packet);
            await _context.SaveChangesAsync();

            return CreatedAtAction(nameof(GetPacket), new { id = packet.Id }, packet);
        }

        // PUT: api/Packets/5 - обновить пакет (только для админов)
        [HttpPut("{id}")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> UpdatePacket(int id, NetworkPacket packet)
        {
            if (id != packet.Id)
                return BadRequest();

            _context.Entry(packet).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!PacketExists(id))
                    return NotFound();
                throw;
            }

            return NoContent();
        }

        // DELETE: api/Packets/5 - удалить пакет (только для админов)
        [HttpDelete("{id}")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> DeletePacket(int id)
        {
            var packet = await _context.NetworkPackets.FindAsync(id);
            if (packet == null)
                return NotFound();

            _context.NetworkPackets.Remove(packet);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        // GET: api/Packets/threat-score/5 - получить балл угрозы пакета
        [HttpGet("threat-score/{id}")]
        [Authorize(Policy = "AuthorizedUser")]
        public async Task<ActionResult<object>> GetThreatScore(int id)
        {
            var packet = await _context.NetworkPackets.FindAsync(id);
            if (packet == null)
                return NotFound();

            return Ok(new
            {
                PacketId = packet.Id,
                ThreatScore = packet.CalculateThreatScore(),
                Category = packet.GetPacketCategory()
            });
        }

        private bool PacketExists(int id)
        {
            return _context.NetworkPackets.Any(e => e.Id == id);
        }
    }
}