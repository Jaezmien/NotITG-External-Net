using System;
using System.Linq;
using NotITG.External;

namespace NotITG.External.Test
{
	class Program
	{
		static void Main(string[] args)
		{
			bool deep = args.Any(x => x == "--deep");
			Console.WriteLine("Deep? " + deep);
			NotITG nITG = new NotITG();

			if (nITG.Scan(deep))
			{
				Console.WriteLine("Found NotITG!");
				Console.WriteLine("Process ID: " + nITG.Process.Id);
				Console.WriteLine("Build Date: " + nITG.Details.BuildDate);
			}
			else
			{
				Console.WriteLine("NotITG not found!");
			}

			Console.ReadLine();
		}
	}
}
