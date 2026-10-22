namespace Rudy.KubePath;

internal static class Program
{
    public static int Main(string[] args)
    {
        try
        {
            return new CliApplication().Run(args);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Unexpected failure: {ex.Message}");
            return 3;
        }
    }
}
