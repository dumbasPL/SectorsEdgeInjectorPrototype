using System;
using System.Threading;

namespace Game
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            while (true)
            {
                Console.WriteLine("Hello! " + DateTime.Now.ToString());
                Thread.Sleep(1000);
            }
        }
    }
}
