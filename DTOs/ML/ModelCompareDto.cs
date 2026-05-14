namespace TrafficAnalysisAPI.DTOs.ML
{
    // Результат сравнения двух моделей на одной сессии.
    // Возвращается из POST /api/ml/compare?sessionId=X

    public class ModelCompareResultDto
    {
        public int SessionId { get; set; }
        public int TotalFlows { get; set; }

        // Сводка по модели Random Forest
        public ModelSummaryDto RfModel { get; set; } = new();

        // Сводка по модели CatBoost
        public ModelSummaryDto CatBoostModel { get; set; } = new();

        // Согласованность моделей (сколько совпадают)
        public AgreementStatsDto Agreement { get; set; } = new();

        // Попарное сравнение предсказаний на каждом flow
        public List<FlowComparisonRowDto> Comparison { get; set; } = new();
    }

    // Краткая сводка по одной модели в рамках сравнения
    public class ModelSummaryDto
    {
        // Сколько flows эта модель отметила как атаки
        public int AttackFlows { get; set; }

        // Время инференса в мс
        public long ElapsedMs { get; set; }

        // Список признаков на которых модель обучалась
        public List<string> Features { get; set; } = new();

        // Метрики качества (accuracy/f1/roc_auc) из обучения
        public Dictionary<string, object>? Metrics { get; set; }
    }

    // Статистика согласованности двух моделей
    public class AgreementStatsDto
    {
        // Обе модели сказали "атака"
        public int BothAttack { get; set; }

        // Обе модели сказали "норма"
        public int BothNormal { get; set; }

        // Модели разошлись
        public int Disagree { get; set; }

        // Доля согласия: (BothAttack + BothNormal) / Total
        public double AgreementRate { get; set; }
    }

    // Попарное сравнение предсказаний на одном flow
    public class FlowComparisonRowDto
    {
        public int FlowId { get; set; }
        public string SourceIP { get; set; } = "";
        public string DestinationIP { get; set; } = "";
        public int DestinationPort { get; set; }
        public string Protocol { get; set; } = "";

        // RF
        public bool RfIsAttack { get; set; }
        public double RfConfidence { get; set; }
        public string RfThreatLevel { get; set; } = "Low";
        public string RfMethod { get; set; } = "none";

        // CatBoost
        public bool CatBoostIsAttack { get; set; }
        public double CatBoostConfidence { get; set; }
        public string CatBoostThreatLevel { get; set; } = "Low";
        public string CatBoostMethod { get; set; } = "none";

        // Согласны ли модели (обе атака или обе норма)
        public bool Agree { get; set; }
    }
}
