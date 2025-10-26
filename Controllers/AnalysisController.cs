using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TrafficAnalysisAPI.DTOs;
using TrafficAnalysisAPI.Services.Interfaces;

namespace TrafficAnalysisAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AnalysisController : ControllerBase
    {
        private readonly IAnalysisService _analysisService;
        private readonly ILogger<AnalysisController> _logger;

        public AnalysisController(IAnalysisService analysisService, ILogger<AnalysisController> logger)
        {
            _analysisService = analysisService;
            _logger = logger;
        }

        [HttpGet]
        [Authorize(Policy = "AuthorizedUser")]
        [ProducesResponseType(typeof(IEnumerable<AnalysisDto>), StatusCodes.Status200OK)]
        public async Task<ActionResult<IEnumerable<AnalysisDto>>> GetAnalyses()
        {
            var analyses = await _analysisService.GetAllAnalysesAsync();
            return Ok(analyses);
        }

        [HttpGet("{id}")]
        [Authorize(Policy = "AuthorizedUser")]
        [ProducesResponseType(typeof(AnalysisDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<AnalysisDto>> GetAnalysis(int id)
        {
            var analysis = await _analysisService.GetAnalysisByIdAsync(id);

            if (analysis == null)
                return NotFound(new { message = $"Анализ с ID {id} не найден" });

            return Ok(analysis);
        }

        [HttpPost]
        [Authorize(Policy = "AdminOnly")]
        [ProducesResponseType(typeof(AnalysisDto), StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<AnalysisDto>> CreateAnalysis([FromBody] CreateAnalysisDto dto)
        {
            try
            {
                var analysis = await _analysisService.CreateAnalysisAsync(dto);
                return CreatedAtAction(nameof(GetAnalysis), new { id = analysis.Id }, analysis);
            }
            catch (ArgumentException ex)
            {
                return BadRequest(new { message = ex.Message });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating analysis");
                return BadRequest(new { message = "Ошибка при создании анализа" });
            }
        }

        [HttpPut("{id}")]
        [Authorize(Policy = "AdminOnly")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> UpdateAnalysis(int id, [FromBody] CreateAnalysisDto dto)
        {
            var success = await _analysisService.UpdateAnalysisAsync(id, dto);

            if (!success)
                return NotFound(new { message = $"Анализ с ID {id} не найден" });

            return NoContent();
        }

        [HttpDelete("{id}")]
        [Authorize(Policy = "AdminOnly")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> DeleteAnalysis(int id)
        {
            var success = await _analysisService.DeleteAnalysisAsync(id);

            if (!success)
                return NotFound(new { message = $"Анализ с ID {id} не найден" });

            return NoContent();
        }

        [HttpGet("report/{id}")]
        [Authorize(Policy = "AuthorizedUser")]
        [ProducesResponseType(typeof(AnalysisReportDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<AnalysisReportDto>> GetReport(int id)
        {
            var report = await _analysisService.GetAnalysisReportAsync(id);

            if (report == null)
                return NotFound(new { message = $"Анализ с ID {id} не найден" });

            return Ok(report);
        }

        [HttpPost("update-confidence/{id}")]
        [Authorize(Policy = "AdminOnly")]
        [ProducesResponseType(StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> UpdateConfidence(int id, [FromBody] double newScore)
        {
            var success = await _analysisService.UpdateConfidenceAsync(id, newScore);

            if (!success)
                return NotFound(new { message = $"Анализ с ID {id} не найден" });

            var analysis = await _analysisService.GetAnalysisByIdAsync(id);

            return Ok(new
            {
                message = "Уверенность модели обновлена",
                newMLScore = analysis!.MLModelScore,
                threatLevel = analysis.ThreatLevel
            });
        }
    }
}