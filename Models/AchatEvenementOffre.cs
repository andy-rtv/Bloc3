using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace BLOC3.Models
{
    public class AchatEvenementOffre
    {
        [Key]
        public int Id_AchatEvenementOffre { get; set; }

        // Foreign keys
        public int AchatId { get; set; }
        public int EvenementId { get; set; }
        public int OffreId { get; set; }

        // Navigation properties
        [ForeignKey("AchatId")]
        public Achat? Achat { get; set; }

        [ForeignKey("EvenementId")]
        public Evenement? Evenement { get; set; }

        [ForeignKey("OffreId")]
        public Offre? Offre { get; set; }

        public ICollection<Ticket> Tickets { get; set; }

        public AchatEvenementOffre()
        {
            Tickets = new List<Ticket>();
        }
    }
}
