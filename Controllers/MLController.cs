using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Python.Runtime;
using System.Text.Json;
using TrafficAnalysisAPI.Data;
using TrafficAnalysisAPI.DTOs.ML;
using TrafficAnalysisAPI.Services.Interfaces;

namespace TrafficAnalysisAPI.Controllers
{
    /// <summary>
    /// Flow-level ML-аналитика:
    ///   - feature-selection: локальный силуэт на сессии
    ///   - flow-analyze:      модель (rf или catboost) на FlowMetrics
    ///   - compare:           A/B сравнение обеих моделей
    ///   - model-meta:        что внутри global_features.json / catboost_features.json
    /// </summary>
    [Route("api/[controller]")]
    [ApiController]
    // [Authorize(Policy = "AdminOnly")]
    public class MLController : ControllerBase
    {
        private readonly ApplicationDbContext _context;
        private readonly IPythonMLService _pythonML;
        private readonly ILogger<MLController> _logger;
        private readonly string _scriptsPath;
        private readonly string _rfMetaPath;
        private readonly string _cbMetaPath;

        public MLController(
            ApplicationDbContext context,
            IPythonMLService pythonML,
            IConfiguration configuration,
            ILogger<MLController> logger)
        {
            _context = context;
            _pythonML = pythonML;
            _logger = logger;
            _scriptsPath = configuration["PythonScripts:Path"] ??
                Path.Combine(Directory.GetCurrentDirectory(), "PythonScripts");

            _rfMetaPath = configuration["PythonScripts:ModelMetaPath"] ??
                Path.Combine(_scriptsPath, "models", "global_features.json");
            _cbMetaPath = configuration["PythonScripts:CatBoostMetaPath"] ??
                Path.Combine(_scriptsPath, "models", "catboost_features.json");
        }

        // =====================================================================
        // GET /api/ml/model-meta?model=rf|catboost
        // =====================================================================
        [HttpGet("model-meta")]
        [ProducesResponseType(typeof(ModelMetaDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status404NotFound)]
        public IActionResult GetModelMeta([FromQuery] string model = "rf")
        {
            var metaPath = model?.ToLower() == "catboost" ? _cbMetaPath : _rfMetaPath;

            if (!System.IO.File.Exists(metaPath))
            {
                return NotFound(new
                {
                    message = $"Модель {model} не обучена. " +
                              $"Запустите train_hybrid_model.py --model_type {model}",
                    expected = metaPath,
                });
            }

            try
            {
                var json = System.IO.File.ReadAllText(metaPath);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;

                var dto = new ModelMetaDto
                {
                    FeatureNames = root.TryGetProperty("feature_names", out var fn)
                        ? JsonSerializer.Deserialize<List<string>>(fn.GetRawText()) ?? new()
                        : new(),
                    ModelVersion = root.TryGetProperty("model_version", out var mv)
                        ? mv.GetString() ?? "" : "",
                    ModelFile = root.TryGetProperty("model_file", out var mf)
                        ? mf.GetString() ?? "" : "",
                    TrainedOn = root.TryGetProperty("trained_on", out var to)
                        ? to.GetString() ?? "" : "",
                    SelectionMethod = root.TryGetProperty("selection_method", out var sm)
                        ? sm.GetString() : null,
                };

                if (root.TryGetProperty("features_by_block", out var fbb))
                {
                    dto.FeaturesByBlock = JsonSerializer.Deserialize<
                        Dictionary<string, List<string>>>(fbb.GetRawText());
                }

                return Ok(dto);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error reading model meta");
                return StatusCode(500, new { message = "Ошибка чтения", error = ex.Message });
            }
        }

        // =====================================================================
        // POST /api/ml/feature-selection?sessionId=X&topK=10
        // =====================================================================
        [HttpPost("feature-selection")]
        [ProducesResponseType(typeof(FeatureSelectionResultDto), StatusCodes.Status200OK)]
        public async Task<ActionResult<FeatureSelectionResultDto>> FeatureSelection(
            [FromQuery] int? sessionId = null,
            [FromQuery] int topK = 10)
        {
            if (topK < 1 || topK > 50)
                return BadRequest(new { message = "topK должен быть от 1 до 50" });

            IQueryable<Models.FlowMetrics> query = _context.FlowMetrics.AsNoTracking();
            if (sessionId.HasValue)
                query = query.Where(f => f.SessionId == sessionId.Value);

            var flows = await query.ToListAsync();
            if (flows.Count == 0)
                return BadRequest(new
                {
                    message = sessionId.HasValue
                        ? $"Сессия {sessionId} не содержит flow-метрик."
                        : "В базе нет flow-метрик. Импортируйте .pcap."
                });

            _logger.LogInformation(
                $"[FeatureSelection] session={sessionId?.ToString() ?? "ALL"}, " +
                $"flows={flows.Count}, topK={topK}");

            try
            {
                string resultJson;
                using (Py.GIL())
                {
                    dynamic sys = Py.Import("sys");
                    sys.path.append(_scriptsPath);
                    dynamic module = Py.Import("feature_selection");

                    var jsonOptions = new JsonSerializerOptions
                    {
                        PropertyNamingPolicy = null,
                        ReferenceHandler = System.Text.Json.Serialization.ReferenceHandler.IgnoreCycles,
                    };
                    string flowsJson = JsonSerializer.Serialize(flows, jsonOptions);

                    dynamic pyResult = module.rank_features(flowsJson, topK);
                    resultJson = pyResult?.ToString() ?? "{}";
                }

                var parsed = JsonSerializer.Deserialize<FeatureSelectionResultDto>(
                    resultJson,
                    new JsonSerializerOptions { PropertyNameCaseInsensitive = true }
                ) ?? new FeatureSelectionResultDto();

                if (!string.IsNullOrEmpty(parsed.Error))
                    return BadRequest(new { message = parsed.Error });

                return Ok(parsed);
            }
            catch (PythonException pex)
            {
                _logger.LogError(pex, "[FeatureSelection] Python error");
                return StatusCode(500, new { message = "Python error", error = pex.Message });
            }
        }

        // =====================================================================
        // POST /api/ml/flow-analyze?sessionId=X&model=rf|catboost
        // =====================================================================
        [HttpPost("flow-analyze")]
        [ProducesResponseType(typeof(FlowMLAnalyzeResultDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<FlowMLAnalyzeResultDto>> FlowAnalyze(
            [FromQuery] int sessionId,
            [FromQuery] string model = "rf")
        {
            var modelLower = (model ?? "rf").ToLower();
            if (modelLower != "rf" && modelLower != "catboost")
                return BadRequest(new { message = "model должно быть 'rf' или 'catboost'" });

            var sw = Stopwatch.StartNew();

            var flows = await _context.FlowMetrics
                .AsNoTracking()
                .Where(f => f.SessionId == sessionId)
                .ToListAsync();

            if (flows.Count == 0)
                return BadRequest(new
                {
                    message = $"Сессия {sessionId} не содержит flow-метрик."
                });

            _logger.LogInformation(
                $"[FlowAnalyze] session={sessionId}, flows={flows.Count}, model={modelLower}");

            try
            {
                var predictions = _pythonML.PredictFlowsBatch(flows, modelLower);

                // Обновляем FlowMetrics с указанием модели в PredictedBy
                var predMap = predictions.ToDictionary(p => p.FlowId);
                var ids = predictions.Select(p => p.FlowId).ToList();
                var trackedFlows = await _context.FlowMetrics
                    .Where(f => ids.Contains(f.Id))
                    .ToListAsync();

                foreach (var flow in trackedFlows)
                {
                    if (predMap.TryGetValue(flow.Id, out var p))
                    {
                        flow.ThreatScore = p.Confidence;
                        flow.ThreatLevel = p.ThreatLevel;
                        flow.PredictedBy = modelLower == "catboost"
                            ? "catboost_ids_v2" : "hybrid_ids_v2";
                    }
                }
                await _context.SaveChangesAsync();
                sw.Stop();

                var metaPath = modelLower == "catboost" ? _cbMetaPath : _rfMetaPath;
                var usedFeatures = LoadFeatureNames(metaPath);

                var result = new FlowMLAnalyzeResultDto
                {
                    SessionId = sessionId,
                    TotalFlows = predictions.Count,
                    AttackFlows = predictions.Count(p => p.IsAttack),
                    AnomalyFlows = predictions.Count(p => p.IsAnomaly),
                    ThreatLevelBreakdown = predictions
                        .GroupBy(p => p.ThreatLevel ?? "Low")
                        .ToDictionary(g => g.Key, g => g.Count()),
                    MethodBreakdown = predictions
                        .GroupBy(p => p.Method ?? "none")
                        .ToDictionary(g => g.Key, g => g.Count()),
                    UsedFeatures = usedFeatures,
                    ElapsedMs = sw.ElapsedMilliseconds,
                    Predictions = predictions,
                };

                _logger.LogInformation(
                    $"[FlowAnalyze-{modelLower}] Готово: " +
                    $"{result.AttackFlows}/{result.TotalFlows} атак, {sw.ElapsedMilliseconds}ms");

                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"[FlowAnalyze-{modelLower}] Error");
                return StatusCode(500, new
                {
                    message = $"Ошибка ML-анализа ({modelLower})",
                    error = ex.Message,
                });
            }
        }

        // =====================================================================
        // POST /api/ml/compare?sessionId=X
        // Запускает обе модели и возвращает их предсказания рядом + метрики сравнения
        // =====================================================================
        [HttpPost("compare")]
        [ProducesResponseType(typeof(ModelCompareResultDto), StatusCodes.Status200OK)]
        [ProducesResponseType(StatusCodes.Status400BadRequest)]
        public async Task<ActionResult<ModelCompareResultDto>> CompareModels(
            [FromQuery] int sessionId)
        {
            var flows = await _context.FlowMetrics
                .AsNoTracking()
                .Where(f => f.SessionId == sessionId)
                .ToListAsync();

            if (flows.Count == 0)
                return BadRequest(new
                {
                    message = $"Сессия {sessionId} не содержит flow-метрик."
                });

            _logger.LogInformation($"[Compare] session={sessionId}, flows={flows.Count}");

            try
            {
                // RF
                var swRf = Stopwatch.StartNew();
                var rfPredictions = _pythonML.PredictFlowsBatch(flows, "rf");
                swRf.Stop();

                // CatBoost
                var swCb = Stopwatch.StartNew();
                var cbPredictions = _pythonML.PredictFlowsBatch(flows, "catboost");
                swCb.Stop();

                // Сопоставляем по FlowId
                var rfMap = rfPredictions.ToDictionary(p => p.FlowId);
                var cbMap = cbPredictions.ToDictionary(p => p.FlowId);

                var sideBySide = new List<FlowComparisonRowDto>();
                int agreeAttack = 0, agreeNorm = 0, disagree = 0;

                foreach (var flow in flows)
                {
                    rfMap.TryGetValue(flow.Id, out var rf);
                    cbMap.TryGetValue(flow.Id, out var cb);

                    bool rfAttack = rf?.IsAttack ?? false;
                    bool cbAttack = cb?.IsAttack ?? false;

                    if (rfAttack && cbAttack) agreeAttack++;
                    else if (!rfAttack && !cbAttack) agreeNorm++;
                    else disagree++;

                    sideBySide.Add(new FlowComparisonRowDto
                    {
                        FlowId = flow.Id,
                        SourceIP = flow.SourceIP,
                        DestinationIP = flow.DestinationIP,
                        DestinationPort = flow.DestinationPort,
                        Protocol = flow.Protocol,
                        RfIsAttack = rfAttack,
                        RfConfidence = rf?.Confidence ?? 0,
                        RfThreatLevel = rf?.ThreatLevel ?? "Low",
                        RfMethod = rf?.Method ?? "none",
                        CatBoostIsAttack = cbAttack,
                        CatBoostConfidence = cb?.Confidence ?? 0,
                        CatBoostThreatLevel = cb?.ThreatLevel ?? "Low",
                        CatBoostMethod = cb?.Method ?? "none",
                        Agree = rfAttack == cbAttack,
                    });
                }

                // Загружаем meta обеих моделей
                var rfMeta = TryLoadMeta(_rfMetaPath);
                var cbMeta = TryLoadMeta(_cbMetaPath);

                var result = new ModelCompareResultDto
                {
                    SessionId = sessionId,
                    TotalFlows = flows.Count,
                    RfModel = new ModelSummaryDto
                    {
                        AttackFlows = rfPredictions.Count(p => p.IsAttack),
                        ElapsedMs = swRf.ElapsedMilliseconds,
                        Features = rfMeta?.FeatureNames ?? new(),
                        Metrics = rfMeta?.Metrics,
                    },
                    CatBoostModel = new ModelSummaryDto
                    {
                        AttackFlows = cbPredictions.Count(p => p.IsAttack),
                        ElapsedMs = swCb.ElapsedMilliseconds,
                        Features = cbMeta?.FeatureNames ?? new(),
                        Metrics = cbMeta?.Metrics,
                    },
                    Agreement = new AgreementStatsDto
                    {
                        BothAttack = agreeAttack,
                        BothNormal = agreeNorm,
                        Disagree = disagree,
                        AgreementRate = flows.Count > 0
                            ? (double)(agreeAttack + agreeNorm) / flows.Count
                            : 0.0,
                    },
                    Comparison = sideBySide,
                };

                _logger.LogInformation(
                    $"[Compare] RF: {result.RfModel.AttackFlows}atk/{swRf.ElapsedMilliseconds}ms, " +
                    $"CB: {result.CatBoostModel.AttackFlows}atk/{swCb.ElapsedMilliseconds}ms, " +
                    $"agreement={result.Agreement.AgreementRate:P1}");

                return Ok(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "[Compare] Error");
                return StatusCode(500, new
                {
                    message = "Ошибка сравнения моделей",
                    error = ex.Message,
                    hint = "Обе модели должны быть обучены: " +
                           "python train_hybrid_model.py --model_type rf && " +
                           "python train_hybrid_model.py --model_type catboost"
                });
            }
        }

        // =====================================================================
        // Вспомогательные методы
        // =====================================================================
        private List<string> LoadFeatureNames(string path)
        {
            if (!System.IO.File.Exists(path)) return new();
            try
            {
                using var doc = JsonDocument.Parse(System.IO.File.ReadAllText(path));
                if (doc.RootElement.TryGetProperty("feature_names", out var fn))
                    return JsonSerializer.Deserialize<List<string>>(fn.GetRawText()) ?? new();
            }
            catch { }
            return new();
        }

        private class LoadedMeta
        {
            public List<string> FeatureNames { get; set; } = new();
            public Dictionary<string, object>? Metrics { get; set; }
        }

        private LoadedMeta? TryLoadMeta(string path)
        {
            if (!System.IO.File.Exists(path)) return null;
            try
            {
                using var doc = JsonDocument.Parse(System.IO.File.ReadAllText(path));
                var result = new LoadedMeta();
                if (doc.RootElement.TryGetProperty("feature_names", out var fn))
                    result.FeatureNames = JsonSerializer.Deserialize<List<string>>(
                        fn.GetRawText()) ?? new();
                if (doc.RootElement.TryGetProperty("metrics", out var m))
                    result.Metrics = JsonSerializer.Deserialize<
                        Dictionary<string, object>>(m.GetRawText());
                return result;
            }
            catch { return null; }
        }
    }
}
