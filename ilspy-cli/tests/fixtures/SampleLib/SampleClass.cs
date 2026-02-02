namespace SampleLib;

public class SampleClass
{
    public string Name { get; set; } = "";
    public int Value { get; set; }

    public string Greet(string greeting)
    {
        return $"{greeting}, {Name}!";
    }

    public int Add(int a, int b)
    {
        return a + b;
    }

    public static bool IsEven(int n)
    {
        return n % 2 == 0;
    }
}

public interface ISampleInterface
{
    void DoWork();
    string GetResult();
}

public struct SampleStruct
{
    public int X;
    public int Y;

    public double Distance()
    {
        return Math.Sqrt(X * X + Y * Y);
    }
}

public enum SampleEnum
{
    None = 0,
    First = 1,
    Second = 2,
    Third = 3
}
