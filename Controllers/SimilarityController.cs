using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Diagnostics;
using System.Text.Json;
using TrafficAnalysisAPI.Data;
using TrafficAnalysisAPI.Services.Interfaces;

namespace TrafficAnalysisAPI.Controllers
{
    /// <summary>
    /// Endpoint для меры сходства между flows.
    /// Реализует формулу из ТЗ диплома:
    ///   Sim = w1·Sim_port + w2·Sim_num + w3·Sim_bin
    ///
    /// Два режима:
    ///   POST /api/similarity/find         — поиск top-K похожих на target flow
    ///   POST /api/similarity/knn-classify — kNN-классификация всех flows
    ///                                       (альтернативный детектор атак)
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    //[Authorize(Policy = "AuthorizedUser")]
    public class SimilarityController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IPythonMLService _pythonML;
        private readonly ILogger<SimilarityController> _logger;

        public SimilarityController(
            ApplicationDbContext context,
            IPythonMLService pythonML,
            ILogger<SimilarityController> logger)
        {
            _context = context;
            _pythonML = pythonML;
            _logger = logger;
        }

        // ============================================================
        // РЕЖИМ 1: Поиск похожих flows
        // ============================================================
        /// <summary>
        /// POST /api/similarity/find?targetFlowId=Y&amp;w1=0.10&amp;w2=0.60&amp;w3=0.30&amp;k=10[&amp;sessionId=X]
        /// Находит топ-K flows наиболее похожих на target по формуле.
        /// </summary>
        [HttpPost("find")]
        public async Task<IActionResult> FindSimilar(
            [FromQuery] int targetFlowId,
            [FromQuery] double w1 = 0.10,
            [FromQuery] double w2 = 0.60,
            [FromQuery] double w3 = 0.30,
            [FromQuery] int k = 10,
            [FromQuery] int? sessionId = null)
        {
            if (k < 1 || k > 100)
                return BadRequest(new { message = "k должен быть от 1 до 100" });

            var stopwatch = Stopwatch.StartNew();

            try
            {
                var target = await _context.FlowMetrics
                    .FirstOrDefaultAsync(f => f.Id == targetFlowId);
                if (target == null)
                    return NotFound(new { message = $"Flow #{targetFlowId} не найден" });

                int searchSessionId = sessionId ?? target.SessionId;

                var flows = await _context.FlowMetrics
                    .Where(f => f.SessionId == searchSessionId)
                    .ToListAsync();

                if (flows.Count < 2)
                    return Ok(new
                    {
                        message = "Недостаточно flows в сессии (минимум 2)",
                        results = Array.Empty<object>(),
                    });

                string resultJson = _pythonML.FindSimilarFlows(
                    flows, targetFlowId, w1, w2, w3, k);

                stopwatch.Stop();

                using var doc = JsonDocument.Parse(resultJson);
                var responseDict = JsonElementToDict(doc.RootElement);
                responseDict["sessionId"] = searchSessionId;
                responseDict["elapsedMs"] = stopwatch.ElapsedMilliseconds;

                _logger.LogInformation(
                    $"[Similarity] find: target={targetFlowId}, k={k}, " +
                    $"elapsed={stopwatch.ElapsedMilliseconds}ms");

                return Ok(responseDict);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[Similarity] find error");
                return StatusCode(500, new
                {
                    message = "Ошибка расчёта сходства",
                    error = ex.Message
                });
            }
        }

        // ============================================================
        // РЕЖИМ 2: kNN-классификация (детектор на мере сходства)
        // ============================================================
        /// <summary>
        /// POST /api/similarity/knn-classify?sessionId=X&amp;w1=0.10&amp;w2=0.60&amp;w3=0.30&amp;k=5&amp;model=rf
        /// Прогоняет ML-модель (RF или CatBoost) для получения "истинных" меток,
        /// затем для каждого flow считает kNN-предсказание на основе меры сходства
        /// и сравнивает с меткой ML.
        ///
        /// Это позволяет оценить кастомную меру сходства как самостоятельный
        /// классификатор, без обучения градиентных деревьев.
        /// </summary>
        [HttpPost("knn-classify")]
        public async Task<IActionResult> KnnClassify(
            [FromQuery] int sessionId,
            [FromQuery] double w1 = 0.10,
            [FromQuery] double w2 = 0.60,
            [FromQuery] double w3 = 0.30,
            [FromQuery] int k = 5,
            [FromQuery] string model = "rf")
        {
            if (k < 1 || k > 50)
                return BadRequest(new { message = "k должен быть от 1 до 50" });

            var stopwatch = Stopwatch.StartNew();

            try
            {
                var flows = await _context.FlowMetrics
                    .Where(f => f.SessionId == sessionId)
                    .ToListAsync();

                if (flows.Count < k + 1)
                    return BadRequest(new
                    {
                        message = $"В сессии {flows.Count} flows, требуется хотя бы {k + 1}"
                    });

                // 1. Получаем "истинные" метки от ML-модели
                _logger.LogInformation(
                    $"[kNN-Sim] Step 1: getting ML labels (model={model}) for {flows.Count} flows");

                var mlPredictions = _pythonML.PredictFlowsBatch(flows, model);
                var labelsByFlowId = new Dictionary<int, bool>();
                for (int i = 0; i < flows.Count && i < mlPredictions.Count; i++)
                {
                    labelsByFlowId[flows[i].Id] = mlPredictions[i].IsAttack;
                }

                // 2. Запускаем kNN-классификацию на тех же flows
                _logger.LogInformation(
                    $"[kNN-Sim] Step 2: kNN classification (k={k})");

                string knnJson = _pythonML.KnnClassifyFlows(
                    flows, labelsByFlowId, w1, w2, w3, k);

                stopwatch.Stop();

                // 3. Парсим JSON и добавляем мета
                using var doc = JsonDocument.Parse(knnJson);
                var responseDict = JsonElementToDict(doc.RootElement);
                responseDict["sessionId"] = sessionId;
                responseDict["modelUsedAsGroundTruth"] = model;
                responseDict["elapsedMs"] = stopwatch.ElapsedMilliseconds;

                _logger.LogInformation(
                    $"[kNN-Sim] Done: {flows.Count} flows, elapsed={stopwatch.ElapsedMilliseconds}ms");

                return Ok(responseDict);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[kNN-Sim] error");
                return StatusCode(500, new
                {
                    message = "Ошибка kNN-классификации",
                    error = ex.Message
                });
            }
        }

        // ============================================================
        // Helper: парсинг JsonElement в Dictionary рекурсивно
        // ============================================================
        private static Dictionary<string, object> JsonElementToDict(JsonElement elem)
        {
            var dict = new Dictionary<string, object>();
            if (elem.ValueKind != JsonValueKind.Object)
                return dict;
            foreach (var prop in elem.EnumerateObject())
            {
                dict[prop.Name] = JsonElementToObject(prop.Value);
            }
            return dict;
        }

        private static object JsonElementToObject(JsonElement elem)
        {
            switch (elem.ValueKind)
            {
                case JsonValueKind.Object:
                    return JsonElementToDict(elem);
                case JsonValueKind.Array:
                    var list = new List<object>();
                    foreach (var item in elem.EnumerateArray())
                        list.Add(JsonElementToObject(item));
                    return list;
                case JsonValueKind.String:
                    return elem.GetString() ?? "";
                case JsonValueKind.Number:
                    if (elem.TryGetInt64(out var l)) return l;
                    return elem.GetDouble();
                case JsonValueKind.True:
                    return true;
                case JsonValueKind.False:
                    return false;
                case JsonValueKind.Null:
                    return null!;
                default:
                    return elem.GetRawText();
            }
        }
    }
}
