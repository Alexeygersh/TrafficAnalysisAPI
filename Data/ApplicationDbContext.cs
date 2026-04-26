using Microsoft.EntityFrameworkCore;
using TrafficAnalysisAPI.Models;

namespace TrafficAnalysisAPI.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<User> Users { get; set; } = null!;
        public DbSet<TrafficSession> TrafficSessions { get; set; } = null!;
        public DbSet<NetworkPacket> NetworkPackets { get; set; } = null!;
        public DbSet<FlowMetrics> FlowMetrics { get; set; } = null!;

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // ================================================
            // СВЯЗИ
            // ================================================

            // Пакет → Сессия
            modelBuilder.Entity<NetworkPacket>()
                .HasOne(p => p.Session)
                .WithMany(s => s.Packets)
                .HasForeignKey(p => p.SessionId)
                .OnDelete(DeleteBehavior.SetNull);

            // Пакет → Flow (может быть null если пакет не вошёл во flow)
            modelBuilder.Entity<NetworkPacket>()
                .HasOne(p => p.Flow)
                .WithMany()
                .HasForeignKey(p => p.FlowId)
                .OnDelete(DeleteBehavior.SetNull);

            // Flow → Сессия
            modelBuilder.Entity<FlowMetrics>()
                .HasOne(f => f.Session)
                .WithMany(s => s.Flows)
                .HasForeignKey(f => f.SessionId)
                .OnDelete(DeleteBehavior.Cascade);

            // ================================================
            // ИНДЕКСЫ
            // ================================================

            modelBuilder.Entity<User>()
                .HasIndex(u => u.Username)
                .IsUnique();

            modelBuilder.Entity<NetworkPacket>(e =>
            {
                e.HasIndex(p => p.SourceIP);
                e.HasIndex(p => p.DestinationIP);
                e.HasIndex(p => p.Timestamp);
                e.HasIndex(p => p.SessionId);
                e.HasIndex(p => p.FlowId);
            });

            modelBuilder.Entity<FlowMetrics>(e =>
            {
                e.HasIndex(f => f.SessionId);
                e.HasIndex(f => new { f.SourceIP, f.DestinationIP });
                e.HasIndex(f => f.Protocol);
                e.HasIndex(f => f.ThreatLevel);
            });

            // ================================================
            // SEED: ТОЛЬКО ПОЛЬЗОВАТЕЛИ
            // Пакеты и сессии добавляются через импорт .pcap
            // ================================================

            modelBuilder.Entity<User>().HasData(
                new User
                {
                    Id = 1,
                    Username = "admin",
                    PasswordHash = "$2a$12$C83vSlJeLDe9HQKCTtAZauTtlT2s8sVbZtZIvGAmlrAR14wDDRkE.",
                    Role = "Admin",
                    CreatedAt = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                },
                new User
                {
                    Id = 2,
                    Username = "analyst",
                    PasswordHash = "$2a$12$uMJ6PYfgWhWPNFTshq.o1uukT0yYAuju3J6mVv1M32MXtrFhpnYB2",
                    Role = "Analyst",
                    CreatedAt = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                }
            );
        }
    }
}
