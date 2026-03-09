namespace TrafficAnalysisAPI.DTOs.ML
{
    /// <summary>
    /// Результат ML-предсказания для одного IP-источника трафика.
    /// Возвращается endpoint'ом POST /api/clustering/ml-analyze.
    /// </summary>
    public class SourceMLPredictionDto
    {
        /// <summary>IP-адрес источника трафика</summary>
        public required string SourceIP { get; set; }

        /// <summary>Является ли источник атакующим по мнению ML-модели</summary>
        public bool IsAttack { get; set; }

        /// <summary>
        /// Уверенность модели Random Forest в классификации (0.0 – 1.0).
        /// Отражает вероятность класса "атака".
        /// </summary>
        public double Confidence { get; set; }

        /// <summary>Уровень угрозы: Low / Medium / High / Critical</summary>
        public required string ThreatLevel { get; set; }

        /// <summary>
        /// Метод обнаружения:
        ///   supervised   — обнаружен Random Forest (известная атака)
        ///   unsupervised — обнаружен Isolation Forest (zero-day аномалия)
        ///   both         — обнаружен обоими методами
        ///   none         — не обнаружен
        /// </summary>
        public required string Method { get; set; }

        /// <summary>Предсказание Random Forest: 0 = норма, 1 = атака</summary>
        public int RfPrediction { get; set; }

        /// <summary>Является ли источник аномалией по Isolation Forest</summary>
        public bool IsAnomaly { get; set; }
    }

    /// <summary>
    /// Запрос на ML-анализ источников трафика сессии.
    /// </summary>
    public class MLAnalyzeRequestDto
    {
        /// <summary>ID сессии для анализа (обязательно)</summary>
        public int SessionId { get; set; }
    }

    /// <summary>
    /// Сводный результат ML-анализа всей сессии.
    /// </summary>
    public class MLAnalyzeResultDto
    {
        public int SessionId { get; set; }
        public int TotalSources { get; set; }
        public int AttackSources { get; set; }
        public int AnomalySources { get; set; }
        public required List<SourceMLPredictionDto> Predictions { get; set; }
    }
}
