using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace RestApiNExApplication1.Domain
{
    public class BaseDomain
    {
        public int Id { get; set; }
        public byte[] RowVersion { get; set; }

        //-----------------
        public string TestText { get; set; }  //string item for T4 generated tests
    }
}
