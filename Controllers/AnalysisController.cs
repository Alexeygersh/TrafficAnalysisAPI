using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using TrafficAnalysisAPI.Data;
using TrafficAnalysisAPI.Models;

namespace TrafficAnalysisAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AnalysisController : ControllerBase
    {
        private readonly ApplicationDbContext _context;

        public AnalysisController(ApplicationDbContext context)
        {
            _context = context;
        }

        // GET: api/Analysis
        [HttpGet]
        [Authorize(Policy = "AuthorizedUser")]
        public async Task<ActionResult<IEnumerable<TrafficAnalysis>>> GetAnalyses()
        {
            return await _context.TrafficAnalyses
                .Include(a => a.Packet)
                .ToListAsync();
        }

        // GET: api/Analysis/5
        [HttpGet("{id}")]
        [Authorize(Policy = "AuthorizedUser")]
        public async Task<ActionResult<TrafficAnalysis>> GetAnalysis(int id)
        {
            var analysis = await _context.TrafficAnalyses
                .Include(a => a.Packet)
                .FirstOrDefaultAsync(a => a.Id == id);

            if (analysis == null)
                return NotFound();

            return analysis;
        }

        // POST: api/Analysis - создать анализ (только админы)
        [HttpPost]
        [Authorize(Policy = "AdminOnly")]
        public async Task<ActionResult<TrafficAnalysis>> CreateAnalysis(TrafficAnalysis analysis)
        {
            // Автоматическая классификация при создании
            analysis.ClassifyThreat();

            _context.TrafficAnalyses.Add(analysis);
            await _context.SaveChangesAsync();

            return CreatedAtAction(nameof(GetAnalysis), new { id = analysis.Id }, analysis);
        }

        // PUT: api/Analysis/5
        [HttpPut("{id}")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> UpdateAnalysis(int id, TrafficAnalysis analysis)
        {
            if (id != analysis.Id)
                return BadRequest();

            _context.Entry(analysis).State = EntityState.Modified;

            try
            {
                await _context.SaveChangesAsync();
            }
            catch (DbUpdateConcurrencyException)
            {
                if (!AnalysisExists(id))
                    return NotFound();
                throw;
            }

            return NoContent();
        }

        // DELETE: api/Analysis/5
        [HttpDelete("{id}")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> DeleteAnalysis(int id)
        {
            var analysis = await _context.TrafficAnalyses.FindAsync(id);
            if (analysis == null)
                return NotFound();

            _context.TrafficAnalyses.Remove(analysis);
            await _context.SaveChangesAsync();

            return NoContent();
        }

        // GET: api/Analysis/report/5 - получить отчет по анализу
        [HttpGet("report/{id}")]
        [Authorize(Policy = "AuthorizedUser")]
        public async Task<ActionResult<string>> GetReport(int id)
        {
            var analysis = await _context.TrafficAnalyses
                .Include(a => a.Packet)
                .FirstOrDefaultAsync(a => a.Id == id);

            if (analysis == null)
                return NotFound();

            return Ok(new { report = analysis.GenerateReport() });
        }

        // POST: api/Analysis/update-confidence/5 - обновить уверенность модели
        [HttpPost("update-confidence/{id}")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> UpdateConfidence(int id, [FromBody] double newScore)
        {
            var analysis = await _context.TrafficAnalyses.FindAsync(id);
            if (analysis == null)
                return NotFound();

            analysis.UpdateConfidence(newScore);
            await _context.SaveChangesAsync();

            return Ok(new
            {
                message = "Уверенность модели обновлена",
                newMLScore = analysis.MLModelScore,
                threatLevel = analysis.ThreatLevel
            });
        }

        private bool AnalysisExists(int id)
        {
            return _context.TrafficAnalyses.Any(e => e.Id == id);
        }
    }
}