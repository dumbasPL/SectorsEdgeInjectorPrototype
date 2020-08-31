using System;

namespace Hack
{
    public class Evil
    {

        public static void Main()
        {
            ConsoleColor cc = Console.ForegroundColor;
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine("Evil cheat!");
            Console.ForegroundColor = cc;
        }

    }
}
