namespace Fabric.Net.Fabric.Models
{
    public class EnrollmentResponse
    {
        public Result result { get; set; }

        public class Result
        {
            public string Cert { get; set; }
        }
    }
}
