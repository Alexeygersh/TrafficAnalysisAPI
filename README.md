# TrafficAnalysisAPI

## 📋 Требования

- .NET 9.0 SDK
- PostgreSQL 14+

# Логика работы системы анализа сетевого трафика

## 🎯 Общая концепция

Система предназначена для:
1. **Сбора** сетевых пакетов
2. **Анализа** трафика с помощью ML-модели
3. **Классификации** угроз
4. **Генерации** отчетов для аналитиков

---

## 📊 Архитектура системы

```
┌──────────────────────────────────────────────────────────┐
│                      CLIENT LAYER                        │
│  (Postman) Swagger / Angular                             │
└────────────────────┬─────────────────────────────────────┘
                     │ HTTP/HTTPS + JWT Bearer Token
                     ▼
┌────────────────────────────────────────────────────────────────────┐
│                        ASP.NET Core Web API                        │
│                                                                    │
│    ┌──────────────────────────────────────────────────────────┐    |
│    │                  AUTHENTICATION LAYER                    │    │
│    │  ┌────────────────────────────────────────────────────┐  │    │
│    │  │  JWT Middleware                                    │  │    │
│    │  │  - Проверка токена                                 │  │    │
│    │  │  - Извлечение Claims (User, Role)                  │  │    │
│    │  │  - Policy-based authorization                      │  │    │
│    │  └────────────────────────────────────────────────────┘  │    │
│    └────────────────────┬─────────────────────────────────────┘    │
│                         │                                          │
│                         ▼                                          │
│    ┌──────────────────────────────────────────────────────────┐    │
│    │                   CONTROLLER LAYER                       │    │
│    │  ┌──────────────┬──────────────┬───────────────────────┐ │    │
│    │  │ Auth         │ Packets      │ Analysis              │ │    │
│    │  │ Controller   │ Controller   │ Controller            │ │    │
│    │  └──────────────┴──────────────┴───────────────────────┘ │    │
│    │  ┌──────────────┬──────────────────────────────────────┐ │    │
│    │  │ Sessions     │ Reports                              │ │    │
│    │  │ Controller   │ Controller (LINQ запросы)            │ │    │
│    │  └──────────────┴──────────────────────────────────────┘ │    │
│    └────────────────────┬─────────────────────────────────────┘    │
│                         │                                          │
│                         ▼                                          │
│    ┌──────────────────────────────────────────────────────────┐    │
│    │                 BUSINESS LOGIC LAYER                     │    │
│    │  (Методы в моделях)                                      │    │
│    │  ┌────────────────────────────────────────────────────┐  │    │
│    │  │ NetworkPacket:                                     │  │    │
│    │  │  - CalculateThreatScore()                          │  │    │
│    │  │  - GetPacketCategory()                             │  │    │
│    │  │  - IsFromSameSource()                              │  │    │
│    │  └────────────────────────────────────────────────────┘  │    │
│    │  ┌────────────────────────────────────────────────────┐  │    │
│    │  │ TrafficAnalysis:                                   │  │    │
│    │  │  - ClassifyThreat()                                │  │    │
│    │  │  - GenerateReport()                                │  │    │
│    │  │  - UpdateConfidence()                              │  │    │
│    │  └────────────────────────────────────────────────────┘  │    │
│    │  ┌────────────────────────────────────────────────────┐  │    │
│    │  │ TrafficSession:                                    │  │    │
│    │  │  - AddPacket()                                     │  │    │
│    │  │  - GetAnomalousPackets()                           │  │    │
│    │  │  - CalculateStatistics()                           │  │    │
│    │  └────────────────────────────────────────────────────┘  │    │
│    └────────────────────┬─────────────────────────────────────┘    │
│                         │                                          │
│                         ▼                                          │
│    ┌──────────────────────────────────────────────────────────┐    │
│    │                 DATA ACCESS LAYER                        │    │
│    │  (Entity Framework Core)                                 │    │
│    │  ┌────────────────────────────────────────────────────┐  │    │
│    │  │ ApplicationDbContext                               │  │    │
│    │  │  - Users                                           │  │    │
│    │  │  - NetworkPackets                                  │  │    │
│    │  │  - TrafficAnalyses                                 │  │    │
│    │  │  - TrafficSessions                                 │  │    │
│    │  └────────────────────────────────────────────────────┘  │    │
│    └────────────────────┬─────────────────────────────────────┘    │
│                         │ Npgsql Provider                          │
│                         │                                          │
└─────────────────────────┼──────────────────────────────────────────┘
                          ▼                       
┌──────────────────────────────────────────────────────────┐
│                  DATABASE LAYER                          │
│              PostgreSQL Database                         │
│  ┌──────────┬──────────┬──────────┬──────────┐           │
│  │ Users    │ Network  │ Traffic  │ Traffic  │           │
│  │          │ Packets  │ Analyses │ Sessions │           │
│  └──────────┴──────────┴──────────┴──────────┘           │
└──────────────────────────────────────────────────────────┘
```

---
## 🔄 Жизненный цикл запроса

### 1️⃣ Авторизация и аутентификация

```
Клиент → POST /api/Auth/login {username, password}
           │
           ▼
    AuthController.Login()
           │
           ├─→ Поиск пользователя в БД
           │   (ApplicationDbContext.Users)
           │
           ├─→ Проверка пароля
           │   (упрощенная проверка или BCrypt)
           │
           ├─→ Генерация JWT токена
           │   - Claims: UserId, Username, Role
           │   - Expiration: 24 часа
           │   - SecretKey из appsettings.json
           │
           └─→ Возврат токена клиенту
                {token, username, role}
```


### Структура JWT токена

```
eyJhbGciO9...
Header (алгоритм) + Payload (данные) + Signature (подпись)

```

### 2️⃣ Авторизованный запрос (с токеном)

```
Клиент → GET /api/Packets
         Header: Authorization: Bearer <token>
           │
           ▼
    [Authorize] Attribute
           │
           ├─→ Middleware проверяет JWT
           │   - Валидность подписи
           │   - Срок действия
           │   - Issuer/Audience
           │
           ├─→ Извлечение Claims
           │   - Role: Admin или Analyst
           │
           ├─→ Проверка Policy
           │   - AuthorizedUser: любой авторизованный
           │   - AdminOnly: только Admin
           │
           ├─→ [Success] → Выполнение метода контроллера
           │
           └─→ [Fail] → 401 Unauthorized или 403 Forbidden
```


## 🎯 Сценарии использования

### Сценарий 1: Создание сессии мониторинга

```
STEP 1: Аналитик начинает новую сессию
────────────────────────────────────────
POST /api/Sessions (Admin token)
{
  "sessionName": "Traffic 2025-09-30",
  "description": "Мониторинг трафика"
}

↓ SessionsController.CreateSession()
  │
  ├─→ Проверка авторизации ([Authorize] AdminOnly)
  │
  ├─→ Валидация DTO (Required, StringLength)
  │
  ├─→ Создание TrafficSession
  │   - StartTime = DateTime.UtcNow
  │   - EndTime = null (сессия активна)
  │
  ├─→ _context.TrafficSessions.Add()
  ├─→ await _context.SaveChangesAsync()
  │
  └─→ Return 201 Created
      Location: /api/Sessions/1
      Body: {id: 1, sessionName: "...", ...}
```

### Сценарий 2: Захват и анализ пакета

```
STEP 2: Поступает сетевой пакет
────────────────────────────────
POST /api/Packets (Admin token)
{
  "sourceIP": "192.168.1.100",
  "destinationIP": "203.0.113.5",
  "port": 3389,
  "protocol": "TCP",
  "packetSize": 2048,
  "sessionId": 1
}

↓ PacketsController.CreatePacket()
  │
  ├─→ Проверка существования сессии
  │   SELECT * FROM TrafficSessions WHERE Id = 1
  │
  ├─→ Создание NetworkPacket
  │   - Timestamp = DateTime.UtcNow
  │
  ├─→ Сохранение в БД
  │   INSERT INTO NetworkPackets (...)
  │
  └─→ Return 201 Created {id: 42, ...}


STEP 3: ML-модель анализирует пакет
────────────────────────────────────
POST /api/Analysis (Admin token)
{
  "packetId": 42,
  "mlModelScore": 0.87,
  "description": "Подозрительное RDP подключение"
}

↓ AnalysisController.CreateAnalysis()
  │
  ├─→ Создание TrafficAnalysis
  │
  ├─→ БИЗНЕС-ЛОГИКА: analysis.ClassifyThreat()
  │   ┌────────────────────────────────────┐
  │   │ if (MLModelScore >= 0.8)           │
  │   │   ThreatLevel = "Critical"         │
  │   │   IsMalicious = true               │
  │   │ else if (MLModelScore >= 0.6)      │
  │   │   ThreatLevel = "High"             │
  │   │ ...                                │
  │   └────────────────────────────────────┘
  │   Результат: ThreatLevel = "Critical", IsMalicious = true
  │
  ├─→ Сохранение в БД
  │   INSERT INTO TrafficAnalyses (...)
  │
  └─→ Return 201 Created
      {id: 5, threatLevel: "Critical", isMalicious: true}
```

### Сценарий 3: Получение сводного отчета

```
STEP 4: Аналитик запрашивает отчет
───────────────────────────────────
GET /api/Reports/suspicious-packets (Analyst token)

↓ ReportsController.GetSuspiciousPackets()
  │
  ├─→ LINQ запрос с объединением таблиц:
  │   ┌────────────────────────────────────────┐
  │   │ _context.NetworkPackets                │
  │   │   .Include(p => p.Analysis)            │
  │   │   .Include(p => p.Session)             │
  │   │   .Where(p => p.Analysis.IsMalicious)  │ ← Фильтр
  │   │   .Select(p => new {               })  │ ← Проекция
  │   │   .OrderByDescending(p => p.MLScore)   │ ← Сортировка
  │   └────────────────────────────────────────┘
  │
  ├─→ EF Core генерирует SQL:
  │   SELECT p.Id, p.SourceIP, p.Port, a.ThreatLevel, ...
  │   FROM NetworkPackets p
  │   INNER JOIN TrafficAnalyses a ON p.Id = a.PacketId
  │   LEFT JOIN TrafficSessions s ON p.SessionId = s.Id
  │   WHERE a.IsMalicious = true
  │   ORDER BY a.MLModelScore DESC
  │
  ├─→ PostgreSQL выполняет запрос
  │
  └─→ Return 200 OK
      [
        {packetId: 42, sourceIP: "192.168.1.100", 
         port: 3389, threatLevel: "Critical", ...},
        ...
      ]
```

## 🧮 Бизнес-логика

### Расчет балла угрозы (NetworkPacket.CalculateThreatScore)

```csharp
// Вызов через GET /api/Packets/threat-score/42

public double CalculateThreatScore()
{...}

// Пример:
// Port = 3389 (RDP) → +30
// PacketSize = 2048 → +20
// Protocol = TCP → +0
// ИТОГО: 50 баллов (Medium threat)
```

### Классификация угроз (TrafficAnalysis.ClassifyThreat)

```csharp
// Вызывается автоматически при POST /api/Analysis

public void ClassifyThreat()
{...}

// Пример: MLModelScore = 0.87 
// → ThreatLevel = "Critical", IsMalicious = true
```

### Поиск аномалий (TrafficSession.GetAnomalousPackets)

```csharp
// Вызов через GET /api/Sessions/anomalous-packets/1

public List<NetworkPacket> GetAnomalousPackets()
{...}

// Логика:
// 1. Для каждого пакета вызывается CalculateThreatScore()
// 2. Пакеты с баллом > 50 считаются аномальными
// 3. Сортировка по убыванию балла
// 4. Возврат списка
```

### Статистика сессии (TrafficSession.CalculateStatistics)

```csharp
// Вызов через GET /api/Sessions/statistics/1

public Dictionary<string, object> CalculateStatistics()
{...}

```


## 🚀 Установка и запуск

### 1. Клонирование репозитория

```bash
git clone <your-repo-url>
cd TrafficAnalysisAPI
```

### 2. Настройка базы данных PostgreSQL

Создайте базу данных:

```sql
CREATE DATABASE TrafficAnalysisDB;
```

Обновите строку подключения в `appsettings.json`:

```json
"ConnectionStrings": {
  "DefaultConnection": "Host=localhost;Port=5432;Database=TrafficAnalysisDB;Username=postgres;Password=ваш_пароль"
}
```

## Шаг 3: Установка пакетов

```bash
dotnet add package Microsoft.EntityFrameworkCore
dotnet add package Microsoft.EntityFrameworkCore.Design
dotnet add package Npgsql.EntityFrameworkCore.PostgreSQL
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package BCrypt.Net-Next
```


### 4. Применение миграций

```bash
dotnet ef migrations add InitialCreate
dotnet ef database update
```
или через nuget console

```bash
Add-Migration InitialCreate
Update-Database
```

Или миграции применятся автоматически при первом запуске.

### 5. Запуск приложения

```bash
dotnet run
```

API будет доступен по адресу: `https://localhost:port`

Swagger UI: `https://localhost:port/swagger`

## 👥 Учетные данные по умолчанию

### Администратор
- **Username:** `admin`
- **Password:** `Admin123!`
- **Роль:** Admin (может добавлять данные)

### Аналитик
- **Username:** `analyst`
- **Password:** `Analyst123!`
- **Роль:** Analyst (только просмотр отчетов)

## 📚 Основная структура проекта

```
TrafficAnalysisAPI/
├── Controllers/
│   ├── AuthController.cs          # Авторизация JWT
│   ├── PacketsController.cs       # CRUD для пакетов
│   ├── AnalysisController.cs      # CRUD для анализа
│   ├── SessionsController.cs      # CRUD для сессий
│   └── ReportsController.cs       # Сводные отчеты (LINQ)
├── Models/
│   └── Models.cs                  # NetworkPacket, TrafficAnalysis, TrafficSession, User
├── Data/
│   └── ApplicationDbContext.cs    # Контекст БД
├── Program.cs                     # Конфигурация приложения
└── appsettings.json              # Настройки
```

### Получение токена

```http
POST /api/Auth/login
Content-Type: application/json

{
  "username": "admin",
  "password": "Admin123!"
}
```

Ответ:
```json
{
  "token": "eyJhbGciOiJIUzI1N...",
  "username": "admin",
  "role": "Admin"
}
```

### Использование токена

Добавьте заголовок к запросам:
```
Authorization: Bearer <ваш_токен>
```

## 📊 API Endpoints

### Авторизация
- `POST /api/Auth/login` - Получить JWT токен

### Пакеты (NetworkPackets)
- `GET /api/Packets` - Все пакеты (требует авторизации)
- `GET /api/Packets/{id}` - Пакет по ID
- `POST /api/Packets` - Создать пакет (только Admin)
- `PUT /api/Packets/{id}` - Обновить пакет (только Admin)
- `DELETE /api/Packets/{id}` - Удалить пакет (только Admin)
- `GET /api/Packets/threat-score/{id}` - Балл угрозы

### Анализ (TrafficAnalysis)
- `GET /api/Analysis` - Все результаты анализа
- `GET /api/Analysis/{id}` - Анализ по ID
- `POST /api/Analysis` - Создать анализ (только Admin)
- `PUT /api/Analysis/{id}` - Обновить
- `DELETE /api/Analysis/{id}` - Удалить
- `GET /api/Analysis/report/{id}` - Получить отчет
- `POST /api/Analysis/update-confidence/{id}` - Обновить ML-скор

### Сессии (TrafficSessions)
- `GET /api/Sessions` - Все сессии
- `GET /api/Sessions/{id}` - Сессия по ID
- `POST /api/Sessions` - Создать сессию (только Admin)
- `PUT /api/Sessions/{id}` - Обновить
- `DELETE /api/Sessions/{id}` - Удалить
- `GET /api/Sessions/statistics/{id}` - Статистика сессии
- `GET /api/Sessions/anomalous-packets/{id}` - Аномальные пакеты
- `POST /api/Sessions/close/{id}` - Завершить сессию

### Отчеты (Reports) - LINQ запросы
Все требуют авторизации:

1. `GET /api/Reports/suspicious-packets` - Подозрительные пакеты с анализом
2. `GET /api/Reports/threats-by-protocol` - Угрозы по протоколам
3. `GET /api/Reports/top-malicious-ips?top=10` - Топ вредоносных IP
4. `GET /api/Reports/source-history/{ip}` - История источника
5. `GET /api/Reports/time-based-summary?hours=24` - Сводка по времени
6. `GET /api/Reports/session-detailed/{id}` - Детальный отчет по сессии

## 🧪 Тестирование

### С помощью Postman

1. Импортируйте коллекцию `TrafficAnalysisAPI_postman_collection.json`
2. Запустите запрос "Login as Admin"
3. Токен автоматически сохранится в переменных
4. Тестируйте остальные endpoints

### С помощью Swagger

1. Откройте `https://localhost:port/swagger`
2. Используйте кнопку "Authorize" (🔓)
3. Введите токен в формате: `Bearer <ваш_токен>`
4. Тестируйте API через UI



## 📄 Лицензия

Учебный проект


