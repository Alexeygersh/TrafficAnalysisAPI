using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi;
using Python.Runtime;
using System.Reflection.Metadata;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json.Serialization;
using System.Xml.Linq;
using TrafficAnalysisAPI.Data;
using TrafficAnalysisAPI.Services.Implementations;
using TrafficAnalysisAPI.Services.Interfaces;

Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
var builder = WebApplication.CreateBuilder(args);

// === PYTHON.NET ИНИЦИАЛИЗАЦИЯ (ОДИН РАЗ!) ===
string pythonDll;
if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
{
    pythonDll = @"C:\Users\agers\AppData\Local\Programs\Python\Python313\python313.dll";
}
else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
{
    pythonDll = "/usr/lib/x86_64-linux-gnu/libpython3.13.so";
}
else
{
    pythonDll = "/Library/Frameworks/Python.framework/Versions/3.13/lib/libpython3.13.dylib";
}

try
{
    Runtime.PythonDLL = pythonDll;
    PythonEngine.Initialize();
    PythonEngine.BeginAllowThreads();
    Console.WriteLine("Python.NET initialized successfully");
}
catch (Exception ex)
{
    Console.WriteLine($"Python.NET initialization failed: {ex.Message}");
    // Не прерываем запуск, API будет работать без ML-функций
}

// === ЛОГИРОВАНИЕ ===
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

// === DATABASE ===
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// === РЕГИСТРАЦИЯ СЕРВИСОВ ===
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IPacketService, PacketService>();
builder.Services.AddScoped<IAnalysisService, AnalysisService>();
builder.Services.AddScoped<ISessionService, SessionService>();
builder.Services.AddScoped<IReportService, ReportService>();
builder.Services.AddScoped<IPythonMLService, PythonMLService>();

// === KESTREL ===
builder.WebHost.ConfigureKestrel(options =>
{
    options.Configure(builder.Configuration.GetSection("Kestrel"));
});

// === JWT AUTHENTICATION ===
var jwtSettings = builder.Configuration.GetSection("JwtSettings");
var secretKey = jwtSettings["SecretKey"] ?? throw new InvalidOperationException("JWT SecretKey не настроен");

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSettings["Issuer"],
            ValidAudience = jwtSettings["Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey)),
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminOnly", policy => policy.RequireRole("Admin"));
    options.AddPolicy("AuthorizedUser", policy => policy.RequireAuthenticatedUser());
});

// === CORS ===
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAngular", policy =>
    {
        policy.WithOrigins("http://localhost:4200", "https://localhost:4200")
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();
    });
});

// === CONTROLLERS ===
builder.Services.AddControllers()
    .AddJsonOptions(options =>
    {
        options.JsonSerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
        options.JsonSerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
        options.JsonSerializerOptions.MaxDepth = 32;
    });

// === SWAGGER ===
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "Traffic Analysis API",
        Version = "v1.1",
        Description = "API для анализа сетевого трафика с ML-кластеризацией"
    });

    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Bearer {token}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        //Type = SecuritySchemeType.ApiKey,
        //Scheme = "Bearer"
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT"
    });
    /*
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            Array.Empty<string>()
        }
    });


    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        [new OpenApiSecuritySchemeReference("Bearer", document)] = Array.Empty<string>()
    });
    */

});

// === BUILD APP ===
var app = builder.Build();

// === АВТОМАТИЧЕСКОЕ ПРИМЕНЕНИЕ МИГРАЦИЙ ===
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

    try
    {
        logger.LogInformation("Applying database migrations...");
        db.Database.Migrate();
        logger.LogInformation("Database migrations applied successfully");
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error during migration");
        throw;
    }
}

// === MIDDLEWARE ===
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Traffic Analysis API v1.1");
        c.RoutePrefix = string.Empty;
    });
}

app.UseHttpsRedirection();
app.UseCors("AllowAngular");

// Логирование запросов
app.Use(async (context, next) =>
{
    var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();
    logger.LogInformation($"{context.Request.Method} {context.Request.Path}");
    logger.LogInformation($"Origin: {context.Request.Headers["Origin"]}");
    await next();
    logger.LogInformation($"Response: {context.Response.StatusCode}");
});

app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

// === ОЧИСТКА PYTHON ===
var lifetime = app.Services.GetRequiredService<IHostApplicationLifetime>();
lifetime.ApplicationStopping.Register(() =>
{
    try
    {
        PythonEngine.Shutdown();
        Console.WriteLine("Python.NET shutdown successfully");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"Error shutting down Python: {ex.Message}");
    }
});

app.Run();
Encoding.GetEncoding(1251);
