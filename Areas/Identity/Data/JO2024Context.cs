using BLOC3.Areas.Identity.Data;
using BLOC3.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using System.Net.Sockets;
using System;

namespace BLOC3.Areas.Identity.Data;

public class JO2024Context : IdentityDbContext<JO2024User>
{
    public JO2024Context(DbContextOptions<JO2024Context> options)
        : base(options)
    {
    }
    public DbSet<Achat>? Achats { get; set; }
    public DbSet<Ticket>? Tickets { get; set; }
    public DbSet<Evenement>? Evenements { get; set; }
    public DbSet<Offre>? Offres { get; set; }
    public DbSet<AchatEvenementOffre>? AchatEvenementOffres { get; set; }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        // Configure Achat relationship
        builder.Entity<Achat>()
            .HasOne(a => a.Utilisateur)
            .WithMany(u => u.Achats)
            .HasForeignKey(a => a.Id_Utilisateur);

        // Configure Ticket relationship with JO2024User
        builder.Entity<Ticket>()
            .HasOne(t => t.Utilisateur)
            .WithMany(u => u.Tickets)
            .HasForeignKey(t => t.Id_Utilisateur);

        // Configure Ticket relationship with AchatEvenementOffre
        builder.Entity<Ticket>()
            .HasOne(t => t.AchatEvenementOffre)
            .WithMany(aeo => aeo.Tickets)
            .HasForeignKey(t => t.Id_AchatEvenementOffre)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
