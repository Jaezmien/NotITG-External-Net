using System;
using System.Runtime.InteropServices;
using System.Diagnostics;

namespace NotITG.External
{
	using System.Linq;
	using System.Text;
	using ProcessHandler;
	using Details;

	public class NotITG
	{
		public NotITGVersionNumber Version;
		public INotITGVersion Details;
		public Process Process = null;
		public ProcessMemory Memory = null;

		private string gamePath;
		public string GamePath { get => gamePath; }

		public bool Connected { get { return this.Process != null; } }

		private ProcessMemory GetMemoryReader(int processID)
		{
			if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
				return new ProcessMemoryWindows(processID);
			if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
				return new ProcessMemoryLinux(processID);

			throw new Exception("OS not handled.");
		}

		public bool Scan(bool deep = false)
		{
			if (Connected) return true;

			var processes = Process.GetProcesses();
			if (!deep)
			{
				foreach (var process in processes)
				{
					foreach (var detail_key in NotITGVersions.Versions.Keys)
					{
						var details = NotITGVersions.Versions[detail_key];
						try
						{
							if (process.MainModule.FileName.Split('\\').LastOrDefault().ToLower().Equals(details.Filename.ToLower()))
							{
								Version = detail_key;
								Process = process;
								Details = details;
								Memory = GetMemoryReader(process.Id);
								gamePath = process.MainModule.FileName;
								return true;
							}
						}
						catch (ProcessMemoryPrivilegeException ex)
						{
							Console.WriteLine(ex);
							return false;
						}

					}
				}
			}
			else
			{
				foreach (var process in processes)
				{
					try
					{
						var memory = GetMemoryReader(process.Id);

						foreach (var detail_key in NotITGVersions.Versions.Keys)
						{
							var detail = NotITGVersions.Versions[detail_key];
							try
							{
								byte[] version_byte = Encoding.ASCII.GetBytes(detail.BuildDate.ToString());
								string read_date = Encoding.ASCII.GetString(memory.Read(detail.BuildAddress, (uint)version_byte.Length));
								if (read_date.ToLower().Equals(detail.BuildDate.ToString().ToLower()))
								{
									Version = detail_key;
									Process = process;
									Memory = memory;
									Details = detail;
									gamePath = process.MainModule.FileName;
									return true;
								}
							}
							catch { }
						}

						memory.Close();
					}
					catch (ProcessMemoryPrivilegeException ex)
					{
						Console.WriteLine(ex);
						return false;
					}
				}
			}

			return false;
		}

		public bool ScanFromProcessID(int pid)
		{
			if (Connected) return true;

			try
			{
				var process = Process.GetProcessById(pid);
				var memory = GetMemoryReader(process.Id);

				foreach (var detail_key in NotITGVersions.Versions.Keys)
				{
					var detail = NotITGVersions.Versions[detail_key];
					try
					{
						byte[] version_byte = Encoding.ASCII.GetBytes(detail.BuildDate.ToString());
						string read_date = Encoding.ASCII.GetString(memory.Read(detail.BuildAddress, (uint)version_byte.Length));
						if (read_date.ToLower().Equals(detail.BuildDate.ToString().ToLower()))
						{
							Version = detail_key;
							Process = process;
							Memory = memory;
							Details = detail;
							gamePath = process.MainModule.FileName;
							return true;
						}
					}
					catch { }
				}

				memory.Close();
				return false;
			}
			catch (ProcessMemoryPrivilegeException ex)
			{
				Console.WriteLine(ex);
				return false;
			}
			catch (ArgumentException)
			{
				return false; // process not running
			}
			catch (Exception)
			{
				return false; // miscellaneous exception
			}
		}

		public void Disconnect()
		{
			if (!Connected) return;
			this.Process = null;
		}

		public bool Heartbeat()
		{
			if (!Connected) return false;

			try
			{
				Process.GetProcessById(Process.Id);
			}
			catch (ArgumentException)
			{
				return false; // process not running
			}
			catch (Exception)
			{
				return false; // miscellaneous exception
			}

			return true;
		}

		public int GetExternal(int index)
		{
			if (!Connected) return 0;
			if (!(index >= 0 && index < Details.Size)) throw new Exception("Index range out of bounds.");

			byte offset = (byte)(index * 4);
			byte[] a = Memory.Read(Details.ExternalAddress + offset, sizeof(int));
			return BitConverter.ToInt32(a, 0);
		}
		public void SetExternal(int index, int flag = 0)
		{
			if (!Connected) return;
			if (!(index >= 0 && index < Details.Size)) throw new Exception("Index range out of bounds.");

			byte[] b = BitConverter.GetBytes(flag);
			byte offset = (byte)(index * 4);
			Memory.Write(Details.ExternalAddress + offset, b);
		}
	}
}

namespace NotITG.External.ProcessHandler
{
	public abstract class ProcessMemory
	{
		public abstract void Close();
		public abstract byte[] Read(IntPtr address, uint bytes_to_read);
		public abstract void Write(IntPtr address, byte[] bytes_to_write);
	}

	public class ProcessMemoryPrivilegeException : Exception
	{
		public ProcessMemoryPrivilegeException() { }

		public ProcessMemoryPrivilegeException(string message) : base(message) { }

		public ProcessMemoryPrivilegeException(string message, Exception inner) : base(message, inner) { }
	}

	public class ProcessMemoryWindows : ProcessMemory
	{
		[DllImport("kernel32.dll")]
		private static extern IntPtr OpenProcess(UInt32 dwDesiredAccess, Int32 bInheritHandle, UInt32 dwProcessId);
		[DllImport("kernel32.dll")]
		private static extern Int32 CloseHandle(IntPtr hObject);
		[DllImport("kernel32.dll")]
		private static extern Int32 ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [In, Out] byte[] buffer, UInt32 size, out IntPtr lpNumberOfBytesRead);
		[DllImport("kernel32.dll")]
		private static extern Int32 WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [In, Out] byte[] buffer, UInt32 size, out IntPtr lpNumberOfBytesWritten);

		private enum ProcessVM
		{
			READ = 0x10,
			WRITE = 0x20,
			OPERATION = 0x8
		}

		private IntPtr m_hProcess = IntPtr.Zero;
		public ProcessMemoryWindows(int processID)
		{
			if (m_hProcess != IntPtr.Zero) return;
			m_hProcess = OpenProcess((uint)(ProcessVM.READ | ProcessVM.WRITE | ProcessVM.OPERATION), 1, (uint)processID);
		}

		public override void Close()
		{
			if (m_hProcess == IntPtr.Zero) return;
			if (CloseHandle(m_hProcess) == 0)
				throw new Exception("Closehandle Failed");
		}

		public override byte[] Read(IntPtr address, uint bytes_to_read)
		{
			byte[] buffer = new byte[bytes_to_read];
			ReadProcessMemory(m_hProcess, address, buffer, bytes_to_read, out IntPtr _);
			return buffer;
		}
		public override void Write(IntPtr address, byte[] bytes_to_write)
		{
			WriteProcessMemory(m_hProcess, address, bytes_to_write, (uint)bytes_to_write.Length, out IntPtr _);
		}
	}

	public class ProcessMemoryLinux : ProcessMemory
	{
		// 🙏 https://dev.to/v0idzz/linux-memory-manipulation-using-net-core-53ce

		private unsafe struct iovec
		{
			public void* iov_base;
			public int iov_len;
		}

		[DllImport("libc.so.6")]
		private static extern unsafe int process_vm_readv(int pid, iovec* local_iov, ulong liovcnt, iovec* remote_iov, ulong riovcnt, ulong flags);
		[DllImport("libc.so.6")]
		private static extern unsafe int process_vm_writev(int pid, iovec* local_iov, ulong liovcnt, iovec* remote_iov, ulong riovcnt, ulong flags);

		[DllImport("libc.so.6")]
		private static extern uint getuid();

		private int processID = 0;
		public ProcessMemoryLinux(int processID)
		{
			if (getuid() != 0) throw new ProcessMemoryPrivilegeException("ProcessMemoryLinux is constructed without sudo privileges");
			if (this.processID != 0) return;
			this.processID = processID;
		}

		public override void Close()
		{
			if (processID == 0) return;
			processID = 0;
		}

		public override unsafe byte[] Read(IntPtr address, uint bytes_to_read)
		{
			int size = (int)bytes_to_read;
			var ptr = stackalloc byte[size];
			var localIo = new iovec
			{
				iov_base = ptr,
				iov_len = size
			};
			var remoteIo = new iovec
			{
				iov_base = address.ToPointer(),
				iov_len = size
			};

			var res = process_vm_readv(processID, &localIo, 1, &remoteIo, 1, 0);
			if (res == -1) throw new Exception("process_vm_readv returned -1");

			var value = new byte[size];
			Marshal.Copy((IntPtr)ptr, value, 0, size);
			return value;
		}
		public override unsafe void Write(IntPtr address, byte[] bytes_to_write)
		{
			int size = bytes_to_write.Length;
			var ptr = stackalloc byte[size];
			var localIo = new iovec
			{
				iov_base = ptr,
				iov_len = size
			};
			var remoteIo = new iovec
			{
				iov_base = address.ToPointer(),
				iov_len = size
			};

			var res = process_vm_writev(processID, &localIo, 1, &remoteIo, 1, 0);
			if (res == -1) throw new Exception("process_vm_writev returned -1");
		}
	}
}

namespace NotITG.External.Details
{
	using System.Collections.Generic;

	public enum NotITGVersionNumber
	{
		UNKNOWN = 0,

		V1,
		V2,
		V3,
		V3_1,
		V4,
		V4_0_1,
		V4_2,
	}

	public struct INotITGVersion
	{
		public readonly IntPtr BuildAddress;
		public readonly int BuildDate;
		public readonly IntPtr ExternalAddress;
		public readonly int Size;

		public readonly string Filename;

		public INotITGVersion(IntPtr buildAddr, int buildDate, IntPtr extAddr, int size, string name)
		{
			BuildAddress = buildAddr;
			BuildDate = buildDate;
			ExternalAddress = extAddr;
			Size = size;

			Filename = name;
		}
	}

	public class NotITGVersions
	{

		public static readonly Dictionary<NotITGVersionNumber, INotITGVersion> Versions = new Dictionary<NotITGVersionNumber, INotITGVersion>()
		{
			[NotITGVersionNumber.V1] = new INotITGVersion(
				(IntPtr)0x006AED20,
				20161224,
				(IntPtr)0x00896950,
				10,
				"NotITG.exe"
			),
			[NotITGVersionNumber.V2] = new INotITGVersion(
				(IntPtr)0x006B7D40,
				20170405,
				(IntPtr)0x008A0880,
				10,
				"NotITG-170405.exe"
			),
			[NotITGVersionNumber.V3] = new INotITGVersion(
				(IntPtr)0x006DFD60,
				20180617,
				(IntPtr)0x008CC9D8,
				64,
				"NotITG-V3.exe"
			),
			[NotITGVersionNumber.V3_1] = new INotITGVersion(
				(IntPtr)0x006E7D60,
				20180827,
				(IntPtr)0x008BE0F8,
				64,
				"NotITG-V3.1.exe"
			),
			[NotITGVersionNumber.V4] = new INotITGVersion(
				(IntPtr)0x006E0E60,
				20200112,
				(IntPtr)0x008BA388,
				64,
				"NotITG-V4.exe"
			),
			[NotITGVersionNumber.V4_0_1] = new INotITGVersion(
				(IntPtr)0x006C5E40,
				20200126,
				(IntPtr)0x00897D10,
				64,
				"NotITG-V4.0.1.exe"
			),
			[NotITGVersionNumber.V4_2] = new INotITGVersion(
				(IntPtr)0x006FAD40,
				20210420,
				(IntPtr)0x008BFF38,
				256,
				"NotITG-V4.2.0.exe"
			),
		};
	}
}