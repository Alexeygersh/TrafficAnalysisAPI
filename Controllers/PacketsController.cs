using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TrafficAnalysisAPI.DTOs;
using TrafficAnalysisAPI.Services.Interfaces;

namespace TrafficAnalysisAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class PacketsController : ControllerBase
    {
        private readonly IPacketService _packetService;
        private readonly ILogger<PacketsController> _logger;

        public PacketsController(IPacketService packetService, ILogger<PacketsController> logger)
        {
            _packetService = packetService;
            _logger = logger;
        }

        // Получить все пакеты
        [HttpGet]
        [Authorize(Policy = "AuthorizedUser")]
        [ProducesResponseType(typeof(IEnumerable<PacketDto>), StatusCodes.Status200OK)]
        public async Task<ActionResult<IEnumerable<PacketDto>>> GetPackets()
        {
            var packets = await _packetService.GetAllPacketsAsync();
            return Ok(packets);
        }

        // Получить пакет по ID
        [HttpGet("{id}")]
        [Authorize(Policy = "AuthorizedUser")]
        [ProducesResponseType(typeof(PacketDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<PacketDto>> GetPacket(int id)
        {
            var packet = await _packetService.GetPacketByIdAsync(id);

            if (packet == null)
            {
                _logger.LogWarning($"Packet {id} not found");
                return NotFound(new { message = $"Пакет с ID {id} не найден" });
            }

            return Ok(packet);
        }

        // Создать новый пакет
        [HttpPost]
        [Authorize(Policy = "AdminOnly")]
        [ProducesResponseType(typeof(PacketDto), StatusCodes.Status201Created)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<PacketDto>> CreatePacket([FromBody] CreatePacketDto dto)
        {
            try
            {
                var packet = await _packetService.CreatePacketAsync(dto);
                return CreatedAtAction(nameof(GetPacket), new { id = packet.Id }, packet);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating packet");
                return BadRequest(new { message = "Ошибка при создании пакета" });
            }
        }

        // Обновить пакет
        [HttpPut("{id}")]
        [Authorize(Policy = "AdminOnly")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> UpdatePacket(int id, [FromBody] UpdatePacketDto dto)
        {
            var success = await _packetService.UpdatePacketAsync(id, dto);

            if (!success)
                return NotFound(new { message = $"Пакет с ID {id} не найден" });

            return NoContent();
        }

        // Удалить пакет
        [HttpDelete("{id}")]
        [Authorize(Policy = "AdminOnly")]
        [ProducesResponseType(StatusCodes.Status204NoContent)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<IActionResult> DeletePacket(int id)
        {
            var success = await _packetService.DeletePacketAsync(id);

            if (!success)
                return NotFound(new { message = $"Пакет с ID {id} не найден" });

            return NoContent();
        }

        // Получить балл угрозы пакета
        [HttpGet("threat-score/{id}")]
        [Authorize(Policy = "AuthorizedUser")]
        [ProducesResponseType(typeof(ThreatScoreDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public async Task<ActionResult<ThreatScoreDto>> GetThreatScore(int id)
        {
            var score = await _packetService.GetThreatScoreAsync(id);

            if (score == null)
                return NotFound(new { message = $"Пакет с ID {id} не найден" });

            return Ok(score);
        }
    }
}