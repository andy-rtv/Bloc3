namespace BLOC3.Models
{
    public class PanierItem
    {
        public int EvenementId { get; set; }
        public Evenement? Evenement { get; set; }
        public int Quantity { get; set; }
        public int OffreId { get; set; }
        public Offre? Offre { get; set; }
    }
}
