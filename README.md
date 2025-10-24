# TrafficAnalysisAPI

## 📋 Требования

- .NET 9.0 SDK
- PostgreSQL 14+

## 🎯 Общая концепция

Система предназначена для:
1. **Сбора** сетевых пакетов
2. **Анализа** трафика с помощью ML-модели
3. **Классификации** угроз
4. **Генерации** отчетов для аналитиков


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

### Тестовые пользователи

| Логин   | Пароль        | Роль     | Права                          |
|---------|---------------|----------|--------------------------------|
| admin   | Admin123!     | Admin    | Полный доступ (CRUD + отчеты)  |
| analyst | Analyst123!   | Analyst  | Только чтение отчетов          |


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


