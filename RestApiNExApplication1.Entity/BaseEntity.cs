using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace RestApiNExApplication1.Entity
{
    public class BaseEntity
    {
        [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
        [Key]
        public int Id { get; set; }
        public DateTime Created { get; set; }
        public DateTime Modified { get; set; }
        //[ConcurrencyCheck]
        //[Timestamp]
        public byte[] RowVersion { get; set; }

        //-----------------
        [StringLength(50)]
        public string TestText { get; set; }  //string item for T4 generated tests

    }
}
