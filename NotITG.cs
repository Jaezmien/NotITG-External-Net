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

		public bool Connected { get { return this.Process != null; } }
		public string GamePath { get => gamePath; }

		private ProcessMemory GetMemoryReader(int processID)
		{
			if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
				return new ProcessMemoryWindows(processID);
			else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
				return new ProcessMemoryLinux(processID);

			throw new Exception("OS not handled.");
		}

		public bool Scan(bool deep = false)
		{
			if (Connected) return true;

			var processes = Process.GetProcesses();
			if (deep)
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
						catch { }

					}
				}
			}
			else
			{
				foreach (var process in processes)
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
								gamePath = process.MainModule.FileName;
								return true;
							}
						}
						catch { }
					}

					memory.Close();
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
							gamePath = process.MainModule.FileName;
							return true;
						}
					}
					catch { }
				}

				memory.Close();
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
	using System.Runtime.CompilerServices;

	public abstract class ProcessMemory
	{
		public abstract void Close();
		public abstract byte[] Read(IntPtr address, uint bytes_to_read);
		public abstract void Write(IntPtr address, byte[] bytes_to_write);
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

		private int processID = 0;
		public ProcessMemoryLinux(int processID)
		{
			if (this.processID != 0) return;
			this.processID = processID;
		}

		public override void Close()
		{
			if (processID == 0) return;
			this.processID = 0;
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
		public IntPtr BuildAddress;
		public int BuildDate;
		public IntPtr ExternalAddress;
		public int Size;

		public string Filename;
	}

	public class NotITGVersions
	{

		public static readonly Dictionary<NotITGVersionNumber, INotITGVersion> Versions = new Dictionary<NotITGVersionNumber, INotITGVersion>()
		{
			[NotITGVersionNumber.V1] = new INotITGVersion()
			{
				BuildAddress = (IntPtr)0x006AED20,
				BuildDate = 20161224,
				ExternalAddress = (IntPtr)0x00896950,
				Size = 10,
				Filename = "NotITG.exe"
			},
			[NotITGVersionNumber.V2] = new INotITGVersion()
			{
				BuildAddress = (IntPtr)0x006B7D40,
				BuildDate = 20170405,
				ExternalAddress = (IntPtr)0x008A0880,
				Size = 10,
				Filename = "NotITG-170405.exe"
			},
			[NotITGVersionNumber.V3] = new INotITGVersion()
			{
				BuildAddress = (IntPtr)0x006DFD60,
				BuildDate = 20180617,
				ExternalAddress = (IntPtr)0x008CC9D8,
				Size = 64,
				Filename = "NotITG-V3.exe"
			},
			[NotITGVersionNumber.V3_1] = new INotITGVersion()
			{
				BuildAddress = (IntPtr)0x006E7D60,
				BuildDate = 20180827,
				ExternalAddress = (IntPtr)0x008BE0F8,
				Size = 64,
				Filename = "NotITG-V3.1.exe"
			},
			[NotITGVersionNumber.V4] = new INotITGVersion()
			{
				BuildAddress = (IntPtr)0x006E0E60,
				BuildDate = 20200112,
				ExternalAddress = (IntPtr)0x008BA388,
				Size = 64,
				Filename = "NotITG-V4.exe"
			},
			[NotITGVersionNumber.V4_0_1] = new INotITGVersion()
			{
				BuildAddress = (IntPtr)0x006C5E40,
				BuildDate = 20200126,
				ExternalAddress = (IntPtr)0x00897D10,
				Size = 64,
				Filename = "NotITG-V4.0.1.exe"
			},
			[NotITGVersionNumber.V4_2] = new INotITGVersion()
			{
				BuildAddress = (IntPtr)0x006FAD40,
				BuildDate = 20210420,
				ExternalAddress = (IntPtr)0x008BFF38,
				Size = 256,
				Filename = "NotITG-V4.2.0.exe"
			},
		};
	}

	/*public class NotITGDetails
	{
		public NOTITG_VERSION Version { get; set; }
		public string Filename { get; set; }
		public int VersionDate { get; set; }
		public int IndexLimit { get; set; }
		public IntPtr VersionAddress { get; set; }
		public IntPtr ExternalAddress { get; set; }

		public NotITGDetails(NOTITG_VERSION version)
		{
			this.Version = version;
			switch (version)
			{
				case NOTITG_VERSION.V1:
					this.Filename = "NotITG.exe";
					this.VersionDate = 20161224;
					this.VersionAddress = (IntPtr)0x006AED20;
					this.ExternalAddress = (IntPtr)0x00896950;
					this.IndexLimit = 9;
					break;
				case NOTITG_VERSION.V2:
					this.Filename = "NotITG-170405.exe";
					this.VersionDate = 20170405;
					this.VersionAddress = (IntPtr)0x006B7D40;
					this.ExternalAddress = (IntPtr)0x008A0880;
					this.IndexLimit = 9;
					break;
				case NOTITG_VERSION.V3:
					this.Filename = "NotITG-V3.exe";
					this.VersionDate = 20180617;
					this.VersionAddress = (IntPtr)0x006DFD60;
					this.ExternalAddress = (IntPtr)0x008CC9D8;
					this.IndexLimit = 63;
					break;
				case NOTITG_VERSION.V3_1:
					this.Filename = "NotITG-V3.1.exe";
					this.VersionDate = 20180827;
					this.VersionAddress = (IntPtr)0x006E7D60;
					this.ExternalAddress = (IntPtr)0x008BE0F8;
					this.IndexLimit = 63;
					break;
				case NOTITG_VERSION.V4:
					this.Filename = "NotITG-V4.exe";
					this.VersionDate = 20200112;
					this.VersionAddress = (IntPtr)0x006E0E60;
					this.ExternalAddress = (IntPtr)0x008BA388;
					this.IndexLimit = 63;
					break;
				case NOTITG_VERSION.V4_0_1:
					this.Filename = "NotITG-V4.0.1.exe";
					this.VersionDate = 20200126;
					this.VersionAddress = (IntPtr)0x006C5E40;
					this.ExternalAddress = (IntPtr)0x00897D10;
					this.IndexLimit = 63;
					break;
				case NOTITG_VERSION.V4_2:
					this.Filename = "NotITG-V4.2.0.exe";
					this.VersionDate = 20210420;
					this.VersionAddress = (IntPtr)0x006FAD40;
					this.ExternalAddress = (IntPtr)0x008BFF38;
					this.IndexLimit = 255;
					break;
				default:
					throw new Exception("Version unknown!");
			}
		}
	}*/
}