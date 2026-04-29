import joblib
import numpy as np

"""
def print_model_info(pkl_path):
    # Выводит всю информацию о модели
    data = joblib.load(pkl_path)
    
    print("=" * 60)
    print("COMPLETE MODEL INFORMATION")
    print("=" * 60)
    
    # 1. Версия и метаданные
    print(f"\nVersion: {data.get('version', 'unknown')}")
    
    # 2. Features
    print(f"\nFeature Names ({len(data['feature_names'])} total):")
    for i, feat in enumerate(data['feature_names'], 1):
        print(f"  {i:2d}. {feat}")
    
    # 3. Scaler статистика
    scaler = data['scaler']
    print(f"\nScaler Statistics:")
    print(f"  Features seen: {scaler.n_features_in_}")
    print(f"\n  Feature means:")
    for feat, mean in zip(data['feature_names'], scaler.mean_):
        print(f"    {feat:30s}: {mean:10.4f}")
    print(f"\n  Feature scales:")
    for feat, scale in zip(data['feature_names'], scaler.scale_):
        print(f"    {feat:30s}: {scale:10.4f}")
    
    # 4. Random Forest важность признаков
    rf = data['supervised']
    print(f"\nRandom Forest Feature Importances:")
    importances = sorted(
        zip(data['feature_names'], rf.feature_importances_),
        key=lambda x: x[1], 
        reverse=True
    )
    for feat, imp in importances:
        bar = "█" * int(imp * 100)
        print(f"  {feat:30s}: {imp:.6f} {bar}")
    
    # 5. Метрики качества
    if data.get('metrics'):
        print(f"\nModel Metrics:")
        for metric, value in data['metrics'].items():
            if isinstance(value, float):
                print(f"  {metric:30s}: {value:.4f}")
            else:
                print(f"  {metric:30s}: {value}")
    
    # 6. Количество деревьев и листьев
    print(f"\nModel Statistics:")
    print(f"  RF trees: {len(rf.estimators_)}")
    total_leaves = sum(tree.tree_.n_leaves for tree in rf.estimators_)
    avg_leaves = total_leaves / len(rf.estimators_)
    print(f"  Total RF leaves: {total_leaves:,}")
    print(f"  Average leaves per tree: {avg_leaves:.0f}")
    
    # 7. Isolation Forest
    iforest = data['anomaly_detector']
    print(f"  IForest trees: {len(iforest.estimators_)}")
    print(f"  Contamination: {iforest.contamination}")
    
    return data


# Использование
data = print_model_info('C:\\Users\\agers\\D\\RGU\\Diplom\\TrafficAnalysisAPI\\PythonScripts\\models\\hybrid_ids_v2.pkl')


def print_model_info_catboost(pkl_path):
    # Выводит всю информацию о модели с CatBoost
    data = joblib.load(pkl_path)
    
    print("=" * 60)
    print("COMPLETE MODEL INFORMATION (CatBoost)")
    print("=" * 60)
    
    # 1. Версия и метаданные
    print(f"\nVersion: {data.get('version', 'unknown')}")
    
    # 2. Features
    print(f"\nFeature Names ({len(data['feature_names'])} total):")
    for i, feat in enumerate(data['feature_names'], 1):
        print(f"  {i:2d}. {feat}")
    
    # 3. Scaler статистика
    scaler = data['scaler']
    print(f"\nScaler Statistics:")
    print(f"  Features seen: {scaler.n_features_in_}")
    print(f"\n  Feature means:")
    for feat, mean in zip(data['feature_names'], scaler.mean_):
        print(f"    {feat:30s}: {mean:10.4f}")
    print(f"\n  Feature scales:")
    for feat, scale in zip(data['feature_names'], scaler.scale_):
        print(f"    {feat:30s}: {scale:10.4f}")
    
    # 4. CatBoost важность признаков (основной тип)
    cb = data['supervised']
    print(f"\nCatBoost Feature Importances (PredictionValuesChange):")
    fi_pvc = cb.get_feature_importance(type='PredictionValuesChange')
    importances = sorted(
        zip(data['feature_names'], fi_pvc),
        key=lambda x: x[1], 
        reverse=True
    )
    for feat, imp in importances:
        bar = "█" * int(imp * 100 / max(fi_pvc)) if max(fi_pvc) > 0 else ""
        print(f"  {feat:30s}: {imp:.6f} {bar}")
    
    # 5. Дополнительный тип важности (LossFunctionChange)
    print(f"\nCatBoost Feature Importances (LossFunctionChange):")
    fi_lfc = cb.get_feature_importance(type='LossFunctionChange')
    importances_lfc = sorted(
        zip(data['feature_names'], fi_lfc),
        key=lambda x: x[1], 
        reverse=True
    )
    for feat, imp in importances_lfc:
        bar = "█" * int(imp * 100 / max(fi_lfc)) if max(fi_lfc) > 0 else ""
        print(f"  {feat:30s}: {imp:.6f} {bar}")
    
    # 6. Метрики качества
    if data.get('metrics'):
        print(f"\nModel Metrics:")
        for metric, value in data['metrics'].items():
            if isinstance(value, float):
                print(f"  {metric:30s}: {value:.4f}")
            else:
                print(f"  {metric:30s}: {value}")
    
    # 7. Статистика модели CatBoost
    print(f"\nModel Statistics:")
    print(f"  CatBoost iterations: {cb.tree_count_ if hasattr(cb, 'tree_count_') else 'N/A'}")
    print(f"  Best iteration: {cb.best_iteration_ if hasattr(cb, 'best_iteration_') else 'N/A'}")
    
    # Параметры обучения
    print(f"\nTraining Parameters:")
    params = cb.get_params()
    key_params = ['iterations', 'learning_rate', 'depth', 'l2_leaf_reg', 
                  'border_count', 'random_seed', 'loss_function', 'eval_metric']
    for param in key_params:
        if param in params:
            print(f"  {param:30s}: {params[param]}")
    
    # Результаты на валидации
    if hasattr(cb, 'best_score_'):
        print(f"\nValidation Results:")
        if isinstance(cb.best_score_, dict):
            for metric, score in cb.best_score_.items():
                print(f"  Best {metric:25s}: {score:.4f}")
        else:
            print(f"  Best score: {cb.best_score_:.4f}")
    
    # Кривые обучения (если есть)
    if hasattr(cb, 'evals_result_') and cb.evals_result_:
        print(f"\nLearning Curves (last values):")
        for dataset_name, metrics in cb.evals_result_.items():
            print(f"  {dataset_name}:")
            for metric_name, values in metrics.items():
                print(f"    {metric_name:25s}: {values[-1]:.4f}")
    
    # 8. Isolation Forest (если используется)
    iforest = data['anomaly_detector']
    print(f"\nAnomaly Detector (Isolation Forest):")
    print(f"  IForest trees: {len(iforest.estimators_)}")
    print(f"  Contamination: {iforest.contamination}")
    
    # 9. Дополнительная информация о классах
    if hasattr(cb, 'classes_'):
        print(f"\nClasses: {cb.classes_}")
        if hasattr(cb, 'predict_proba'):
            print(f"  Output type: probabilities (multi-class: {len(cb.classes_)})")
    
    return data


def print_model_info_auto(pkl_path):
    # Автоматически определяет тип модели и выводит информацию
    data = joblib.load(pkl_path)
    
    # Определяем тип supervised модели
    supervised_model = data.get('supervised')
    model_type = type(supervised_model).__name__
    
    print(f"\nDetected model type: {model_type}")
    
    if 'CatBoost' in model_type:
        print_model_info_catboost(pkl_path)
    elif 'RandomForest' in model_type:
        # Оригинальная функция для Random Forest
        print_model_info(pkl_path)
    else:
        # Универсальный вывод
        print("=" * 60)
        print(f"COMPLETE MODEL INFORMATION ({model_type})")
        print("=" * 60)
        
        print(f"\nVersion: {data.get('version', 'unknown')}")
        
        print(f"\nFeature Names ({len(data['feature_names'])} total):")
        for i, feat in enumerate(data['feature_names'], 1):
            print(f"  {i:2d}. {feat}")
        
        scaler = data['scaler']
        print(f"\nScaler Statistics:")
        print(f"  Features seen: {scaler.n_features_in_}")
        print(f"\n  Feature means:")
        for feat, mean in zip(data['feature_names'], scaler.mean_):
            print(f"    {feat:30s}: {mean:10.4f}")
        print(f"\n  Feature scales:")
        for feat, scale in zip(data['feature_names'], scaler.scale_):
            print(f"    {feat:30s}: {scale:10.4f}")
        
        print(f"\n{model_type} Feature Importances:")
        if hasattr(supervised_model, 'feature_importances_'):
            importances = sorted(
                zip(data['feature_names'], supervised_model.feature_importances_),
                key=lambda x: x[1], 
                reverse=True
            )
            for feat, imp in importances:
                bar = "█" * int(imp * 100 / max(supervised_model.feature_importances_))
                print(f"  {feat:30s}: {imp:.6f} {bar}")
        
        if data.get('metrics'):
            print(f"\nModel Metrics:")
            for metric, value in data['metrics'].items():
                if isinstance(value, float):
                    print(f"  {metric:30s}: {value:.4f}")
                else:
                    print(f"  {metric:30s}: {value}")
        
        iforest = data['anomaly_detector']
        print(f"\nAnomaly Detector (Isolation Forest):")
        print(f"  IForest trees: {len(iforest.estimators_)}")
        print(f"  Contamination: {iforest.contamination}")
    
    return data


# Использование
data = print_model_info_auto('C:\\Users\\agers\\D\\RGU\\Diplom\\TrafficAnalysisAPI\\PythonScripts\\models\\catboost_ids_v2.pkl')


"""


def print_model_info(pkl_path):
    """Выводит всю информацию о модели"""
    data = joblib.load(pkl_path)
    
    print("=" * 60)
    print("COMPLETE MODEL INFORMATION")
    print("=" * 60)
    
    # 1. Версия и метаданные
    print(f"\nVersion: {data.get('version', 'unknown')}")
    
    # 2. Features
    print(f"\nFeature Names ({len(data['feature_names'])} total):")
    for i, feat in enumerate(data['feature_names'], 1):
        print(f"  {i:2d}. {feat}")
    
    # 3. Scaler статистика
    scaler = data['scaler']
    print(f"\nScaler Statistics:")
    print(f"  Features seen: {scaler.n_features_in_}")
    print(f"\n  Feature means:")
    for feat, mean in zip(data['feature_names'], scaler.mean_):
        print(f"    {feat:30s}: {mean:10.4f}")
    print(f"\n  Feature scales:")
    for feat, scale in zip(data['feature_names'], scaler.scale_):
        print(f"    {feat:30s}: {scale:10.4f}")
    
    # 4. Random Forest важность признаков
    rf = data['supervised']
    print(f"\nRandom Forest Feature Importances:")
    importances = sorted(
        zip(data['feature_names'], rf.feature_importances_),
        key=lambda x: x[1], 
        reverse=True
    )
    for feat, imp in importances:
        bar = "█" * int(imp * 100)
        print(f"  {feat:30s}: {imp:.6f} {bar}")
    
    # 5. Метрики качества
    if data.get('metrics'):
        print(f"\nModel Metrics:")
        for metric, value in data['metrics'].items():
            if isinstance(value, float):
                print(f"  {metric:30s}: {value:.4f}")
            else:
                print(f"  {metric:30s}: {value}")
    
    # 6. Количество деревьев и листьев
    print(f"\nModel Statistics:")
    print(f"  RF trees: {len(rf.estimators_)}")
    total_leaves = sum(tree.tree_.n_leaves for tree in rf.estimators_)
    avg_leaves = total_leaves / len(rf.estimators_)
    print(f"  Total RF leaves: {total_leaves:,}")
    print(f"  Average leaves per tree: {avg_leaves:.0f}")
    
    # 7. Isolation Forest
    iforest = data['anomaly_detector']
    print(f"  IForest trees: {len(iforest.estimators_)}")
    print(f"  Contamination: {iforest.contamination}")
    
    return data


def print_model_info_catboost(pkl_path):
    """Выводит всю информацию о модели с CatBoost"""
    data = joblib.load(pkl_path)
    
    print("=" * 60)
    print("COMPLETE MODEL INFORMATION (CatBoost)")
    print("=" * 60)
    
    # 1. Версия и метаданные
    print(f"\nVersion: {data.get('version', 'unknown')}")
    
    # 2. Features
    print(f"\nFeature Names ({len(data['feature_names'])} total):")
    for i, feat in enumerate(data['feature_names'], 1):
        print(f"  {i:2d}. {feat}")
    
    # 3. Scaler статистика
    scaler = data['scaler']
    print(f"\nScaler Statistics:")
    print(f"  Features seen: {scaler.n_features_in_}")
    print(f"\n  Feature means:")
    for feat, mean in zip(data['feature_names'], scaler.mean_):
        print(f"    {feat:30s}: {mean:10.4f}")
    print(f"\n  Feature scales:")
    for feat, scale in zip(data['feature_names'], scaler.scale_):
        print(f"    {feat:30s}: {scale:10.4f}")
    
    # 4. CatBoost важность признаков (основной тип)
    cb = data['supervised']
    print(f"\nCatBoost Feature Importances (PredictionValuesChange):")
    try:
        fi_pvc = cb.get_feature_importance(type='PredictionValuesChange')
        importances = sorted(
            zip(data['feature_names'], fi_pvc),
            key=lambda x: x[1], 
            reverse=True
        )
        for feat, imp in importances:
            bar = "█" * int(imp * 100 / max(fi_pvc)) if max(fi_pvc) > 0 else ""
            print(f"  {feat:30s}: {imp:.6f} {bar}")
    except Exception as e:
        print(f"  Error getting PredictionValuesChange: {e}")
    
    # 5. Дополнительный тип важности (LossFunctionChange) - требует данные
    print(f"\nCatBoost Feature Importances (LossFunctionChange):")
    try:
        fi_lfc = cb.get_feature_importance(type='LossFunctionChange')
        importances_lfc = sorted(
            zip(data['feature_names'], fi_lfc),
            key=lambda x: x[1], 
            reverse=True
        )
        for feat, imp in importances_lfc:
            bar = "█" * int(imp * 100 / max(fi_lfc)) if max(fi_lfc) > 0 else ""
            print(f"  {feat:30s}: {imp:.6f} {bar}")
    except Exception as e:
        print(f"  LossFunctionChange requires training data. Skipping...")
        print(f"  (Use get_feature_importance(type='LossFunctionChange', data=X_train) if data available)")
    
    # 6. Дополнительный тип важности (FeatureImportance - если есть)
    print(f"\nCatBoost Feature Importances (Built-in):")
    try:
        if hasattr(cb, 'feature_importances_'):
            importances = sorted(
                zip(data['feature_names'], cb.feature_importances_),
                key=lambda x: x[1], 
                reverse=True
            )
            for feat, imp in importances:
                bar = "█" * int(imp * 100 / max(cb.feature_importances_)) if max(cb.feature_importances_) > 0 else ""
                print(f"  {feat:30s}: {imp:.6f} {bar}")
        else:
            print("  No built-in feature_importances_ available")
    except Exception as e:
        print(f"  Error: {e}")
    
    # 7. Метрики качества
    if data.get('metrics'):
        print(f"\nModel Metrics:")
        for metric, value in data['metrics'].items():
            if isinstance(value, float):
                print(f"  {metric:30s}: {value:.4f}")
            else:
                print(f"  {metric:30s}: {value}")
    
    # 8. Статистика модели CatBoost
    print(f"\nModel Statistics:")
    print(f"  CatBoost iterations: {cb.tree_count_ if hasattr(cb, 'tree_count_') else 'N/A'}")
    print(f"  Best iteration: {cb.best_iteration_ if hasattr(cb, 'best_iteration_') else 'N/A'}")
    
    # Параметры обучения
    print(f"\nTraining Parameters:")
    params = cb.get_params()
    key_params = ['iterations', 'learning_rate', 'depth', 'l2_leaf_reg', 
                  'border_count', 'random_seed', 'loss_function', 'eval_metric']
    for param in key_params:
        if param in params:
            print(f"  {param:30s}: {params[param]}")
    
    # Все параметры (опционально)
    print(f"\nAll Parameters:")
    for param, value in params.items():
        print(f"  {param:30s}: {value}")
    
    # Результаты на валидации
    if hasattr(cb, 'best_score_'):
        print(f"\nValidation Results:")
        if isinstance(cb.best_score_, dict):
            for metric, score in cb.best_score_.items():
                print(f"  Best {metric:25s}: {score}")
        else:
            print(f"  Best score: {cb.best_score_:.4f}")
    
    # Кривые обучения (если есть)
    if hasattr(cb, 'evals_result_') and cb.evals_result_:
        print(f"\nLearning Curves (last values):")
        for dataset_name, metrics in cb.evals_result_.items():
            print(f"  {dataset_name}:")
            for metric_name, values in metrics.items():
                print(f"    {metric_name:25s}: {values[-1]:.4f}")
    
    # 9. Isolation Forest (если используется)
    iforest = data['anomaly_detector']
    print(f"\nAnomaly Detector (Isolation Forest):")
    print(f"  IForest trees: {len(iforest.estimators_)}")
    print(f"  Contamination: {iforest.contamination}")
    
    # 10. Дополнительная информация о классах
    if hasattr(cb, 'classes_'):
        print(f"\nClasses: {cb.classes_}")
        if hasattr(cb, 'predict_proba'):
            print(f"  Output type: probabilities (multi-class: {len(cb.classes_)})")
    
    return data


def print_model_info_auto(pkl_path):
    """Автоматически определяет тип модели и выводит информацию"""
    data = joblib.load(pkl_path)
    
    # Определяем тип supervised модели
    supervised_model = data.get('supervised')
    model_type = type(supervised_model).__name__
    
    print(f"\nDetected model type: {model_type}")
    
    if 'CatBoost' in model_type:
        print_model_info_catboost(pkl_path)
    elif 'RandomForest' in model_type:
        # Оригинальная функция для Random Forest
        print_model_info(pkl_path)
    else:
        # Универсальный вывод
        print("=" * 60)
        print(f"COMPLETE MODEL INFORMATION ({model_type})")
        print("=" * 60)
        
        print(f"\nVersion: {data.get('version', 'unknown')}")
        
        print(f"\nFeature Names ({len(data['feature_names'])} total):")
        for i, feat in enumerate(data['feature_names'], 1):
            print(f"  {i:2d}. {feat}")
        
        scaler = data['scaler']
        print(f"\nScaler Statistics:")
        print(f"  Features seen: {scaler.n_features_in_}")
        print(f"\n  Feature means:")
        for feat, mean in zip(data['feature_names'], scaler.mean_):
            print(f"    {feat:30s}: {mean:10.4f}")
        print(f"\n  Feature scales:")
        for feat, scale in zip(data['feature_names'], scaler.scale_):
            print(f"    {feat:30s}: {scale:10.4f}")
        
        print(f"\n{model_type} Feature Importances:")
        if hasattr(supervised_model, 'feature_importances_'):
            importances = sorted(
                zip(data['feature_names'], supervised_model.feature_importances_),
                key=lambda x: x[1], 
                reverse=True
            )
            for feat, imp in importances:
                bar = "█" * int(imp * 100 / max(supervised_model.feature_importances_))
                print(f"  {feat:30s}: {imp:.6f} {bar}")
        
        if data.get('metrics'):
            print(f"\nModel Metrics:")
            for metric, value in data['metrics'].items():
                if isinstance(value, float):
                    print(f"  {metric:30s}: {value:.4f}")
                else:
                    print(f"  {metric:30s}: {value}")
        
        iforest = data['anomaly_detector']
        print(f"\nAnomaly Detector (Isolation Forest):")
        print(f"  IForest trees: {len(iforest.estimators_)}")
        print(f"  Contamination: {iforest.contamination}")
    
    return data


# Использование
data = print_model_info_auto('C:\\Users\\agers\\D\\RGU\\Diplom\\TrafficAnalysisAPI\\PythonScripts\\models\\hybrid_ids_v2.pkl')