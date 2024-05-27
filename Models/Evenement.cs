using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
namespace BLOC3.Models
{
    public enum Genre
    {
        Homme,
        Femme,
        Mixte
    }

    public enum TypeEpreuve
    {
        Olympique,
        Paralympique
    }

    public class Evenement
    {
        [Key]
        public int Id_Evenement { get; set; }

        [Required(ErrorMessage = "Le nom du sport est requis.")]
        public string? SportName { get; set; }

        public string? Description { get; set; }

        [Required(ErrorMessage = "La date de début est requise.")]
        public DateTime DateDebut { get; set; }

        [Required(ErrorMessage = "La date de fin est requise.")]
        public DateTime DateFin { get; set; }

        [Required(ErrorMessage = "Le genre est requis.")]
        public Genre Genre { get; set; }

        [Required(ErrorMessage = "Le type d'épreuve est requis.")]
        public TypeEpreuve TypeEpreuve { get; set; }

        [DataType(DataType.Currency)]
        [Range(0, (double)decimal.MaxValue, ErrorMessage = "Le prix doit être un nombre positif.")]
        public decimal Prix { get; set; }

        public string ImgUrlPath { get; set; } = "/uploads/events/blank.jpg";

        // Navigation properties
        public ICollection<Ticket> Tickets { get; set; }
        public ICollection<AchatEvenementOffre> AchatEvenementOffres { get; set; }

        public Evenement()
        {
            Tickets = new List<Ticket>();
            AchatEvenementOffres = new List<AchatEvenementOffre>();
        }
    }
}
