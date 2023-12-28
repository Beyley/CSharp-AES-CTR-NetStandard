using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace FastAes
{
	/// <summary>
	/// Class that can be used for AES CTR encryption / decryption
	/// </summary>
	public sealed class AesCtr : IDisposable
	{
		/// <summary>
		/// What are allowed key lengths in bytes (128, 192 and 256 bits)
		/// </summary>
		/// <value></value>
		private static readonly int[] AllowedKeyLengths = [16, 24, 32];

		/// <summary>
		/// What is allowed initial counter length in bytes
		/// </summary>
		private const int ALLOWED_COUNTER_LENGTH = 16;

		/// <summary>
		/// Only allowed Initialization vector length in bytes
		/// </summary>
		private const int IV_LENGTH = 16;

		/// <summary>
		/// How many bytes are processed at time
		/// </summary>
		private const int PROCESS_BYTES_AT_TIME = 16;

		/// <summary>
		/// Internal counter
		/// </summary>
		private readonly byte[] _counter = new byte[ALLOWED_COUNTER_LENGTH];

		/// <summary>
		/// Internal transformer for doing encrypt/decrypt transforming
		/// </summary>
		private readonly ICryptoTransform _counterEncryptor;

		/// <summary>
		/// Determines if the objects in this class have been disposed of. Set to true by the Dispose() method.
		/// </summary>
		private bool _isDisposed;

		/// <summary>
		/// Changes counter behaviour according endianness.
		/// </summary>
		private readonly bool _isLittleEndian;

		/// <summary>
		/// AES_CTR constructor
		/// </summary>
		/// <param name="key">Key as byte array. (128, 192 or 256 bits)</param>
		/// <param name="initialCounter">Initial counter as byte array. 16 bytes</param>
		/// <param name="littleEndian">Is initial counter little endian (default false)</param>
		public AesCtr(Span<byte> key, Span<byte> initialCounter, bool littleEndian = false)
		{
			if (key == null) 
			{
				throw new ArgumentNullException(nameof(key));
			}

			int keyLength = key.Length;
			if (AllowedKeyLengths.All(allowed => allowed != keyLength))
			{
				throw new ArgumentException($"Key length must be either {AllowedKeyLengths[0]}, {AllowedKeyLengths[1]} or {AllowedKeyLengths[2]} bytes. Actual: {key.Length}");
			}

			if (initialCounter == null)
			{
				throw new ArgumentNullException(nameof(initialCounter));
			}

			if (ALLOWED_COUNTER_LENGTH != initialCounter.Length)
			{
				throw new ArgumentException($"Initial counter must be {ALLOWED_COUNTER_LENGTH} bytes");
			}

			this._isDisposed = false;

			Aes aes = Aes.Create();
			aes.Mode = CipherMode.ECB;
			aes.Padding = PaddingMode.None;
			
			// Create copy of initial counter since state is kept during the lifetime of AES_CTR
			initialCounter.CopyTo(this._counter.AsSpan()[..ALLOWED_COUNTER_LENGTH]);

			this._isLittleEndian = littleEndian;

			// Initialization vector is always full of zero bytes in CTR mode
			byte[] zeroIv = new byte[IV_LENGTH];
			this._counterEncryptor = aes.CreateEncryptor(key.ToArray(), zeroIv);
		}

		#region Encrypt

		/// <summary>
		/// Encrypt arbitrary-length byte array (input), writing the resulting byte array to preallocated output buffer.
		/// </summary>
		/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
		/// <param name="output">Output byte array, must have enough bytes</param>
		/// <param name="input">Input byte array</param>
		/// <param name="numBytes">Number of bytes to encrypt</param>
		public void EncryptBytes(Span<byte> output, ReadOnlySpan<byte> input, int numBytes)
		{
			if (input == null) throw new ArgumentNullException(nameof(input));
			
			this.WorkBytes(output, input[..numBytes]);
		}

		/// <summary>
		/// Encrypt arbitrary-length byte stream (input), writing the resulting bytes to another stream (output)
		/// </summary>
		/// <param name="output">Output stream</param>
		/// <param name="input">Input stream</param>
		/// <param name="howManyBytesToProcessAtTime">How many bytes to read and write at time, default is 1024</param>
		public void EncryptStream(Stream output, Stream input, int howManyBytesToProcessAtTime = 1024)
		{
			this.WorkStreams(output, input, howManyBytesToProcessAtTime);
		}

		/// <summary>
		/// Async encrypt arbitrary-length byte stream (input), writing the resulting bytes to another stream (output)
		/// </summary>
		/// <param name="output">Output stream</param>
		/// <param name="input">Input stream</param>
		/// <param name="howManyBytesToProcessAtTime">How many bytes to read and write at time, default is 1024</param>
		/// <returns></returns>
		public async Task EncryptStreamAsync(Stream output, Stream input, int howManyBytesToProcessAtTime = 1024)
		{
			await this.WorkStreamsAsync(output, input, howManyBytesToProcessAtTime);
		}

		/// <summary>
		/// Encrypt arbitrary-length byte array (input), writing the resulting byte array to preallocated output buffer.
		/// </summary>
		/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
		/// <param name="output">Output byte array, must have enough bytes</param>
		/// <param name="input">Input byte array</param>
		public void EncryptBytes(Span<byte> output, ReadOnlySpan<byte> input)
		{
			this.WorkBytes(output, input);
		}

		/// <summary>
		/// Encrypt arbitrary-length byte array (input), writing the resulting byte array that is allocated by method.
		/// </summary>
		/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
		/// <param name="input">Input byte array</param>
		/// <param name="numBytes">Number of bytes to encrypt</param>
		/// <returns>Byte array that contains encrypted bytes</returns>
		public byte[] EncryptBytes(ReadOnlySpan<byte> input, int numBytes)
		{
			byte[] returnArray = new byte[numBytes];
			this.WorkBytes(returnArray, input[..numBytes]);
			return returnArray;
		}

		/// <summary>
		/// Encrypt arbitrary-length byte array (input), writing the resulting byte array that is allocated by method.
		/// </summary>
		/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
		/// <param name="input">Input byte array</param>
		/// <returns>Byte array that contains encrypted bytes</returns>
		public byte[] EncryptBytes(ReadOnlySpan<byte> input)
		{
			byte[] returnArray = new byte[input.Length];
			this.WorkBytes(returnArray, input);
			return returnArray;
		}

		/// <summary>
		/// Encrypt string as UTF8 byte array, returns byte array that is allocated by method.
		/// </summary>
		/// <remarks>Here you can NOT swap encrypt and decrypt methods, because of bytes-string transform</remarks>
		/// <param name="input">Input string</param>
		/// <returns>Byte array that contains encrypted bytes</returns>
		public byte[] EncryptString(string input)
		{
			byte[] utf8Bytes = System.Text.Encoding.UTF8.GetBytes(input);
			byte[] returnArray = new byte[utf8Bytes.Length];

			this.WorkBytes(returnArray, utf8Bytes);
			return returnArray;
		}

		#endregion // Encrypt


		#region Decrypt

		/// <summary>
		/// Decrypt arbitrary-length byte array (input), writing the resulting byte array to preallocated output buffer.
		/// </summary>
		/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
		/// <param name="output">Output byte array, must have enough bytes</param>
		/// <param name="input">Input byte array</param>
		/// <param name="numBytes">Number of bytes to encrypt</param>
		public void DecryptBytes(Span<byte> output, ReadOnlySpan<byte> input, int numBytes)
		{
			this.WorkBytes(output, input[0..numBytes]);
		}

		/// <summary>
		/// Decrypt arbitrary-length byte stream (input), writing the resulting bytes to another stream (output)
		/// </summary>
		/// <param name="output">Output stream</param>
		/// <param name="input">Input stream</param>
		/// <param name="howManyBytesToProcessAtTime">How many bytes to read and write at time, default is 1024</param>
		public void DecryptStream(Stream output, Stream input, int howManyBytesToProcessAtTime = 1024)
		{
			this.WorkStreams(output, input, howManyBytesToProcessAtTime);
		}

		/// <summary>
		/// Async decrypt arbitrary-length byte stream (input), writing the resulting bytes to another stream (output)
		/// </summary>
		/// <param name="output">Output stream</param>
		/// <param name="input">Input stream</param>
		/// <param name="howManyBytesToProcessAtTime">How many bytes to read and write at time, default is 1024</param>
		/// <returns></returns>
		public async Task DecryptStreamAsync(Stream output, Stream input, int howManyBytesToProcessAtTime = 1024)
		{
			await this.WorkStreamsAsync(output, input, howManyBytesToProcessAtTime);
		}

		/// <summary>
		/// Decrypt arbitrary-length byte array (input), writing the resulting byte array to preallocated output buffer.
		/// </summary>
		/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
		/// <param name="output">Output byte array, must have enough bytes</param>
		/// <param name="input">Input byte array</param>
		public void DecryptBytes(Span<byte> output, ReadOnlySpan<byte> input)
		{
			this.WorkBytes(output, input);
		}

		/// <summary>
		/// Decrypt arbitrary-length byte array (input), writing the resulting byte array that is allocated by method.
		/// </summary>
		/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
		/// <param name="input">Input byte array</param>
		/// <param name="numBytes">Number of bytes to encrypt</param>
		/// <returns>Byte array that contains decrypted bytes</returns>
		public byte[] DecryptBytes(ReadOnlySpan<byte> input, int numBytes)
		{
			byte[] returnArray = new byte[numBytes];
			this.WorkBytes(returnArray, input[..numBytes]);
			return returnArray;
		}

		/// <summary>
		/// Decrypt arbitrary-length byte array (input), writing the resulting byte array that is allocated by method.
		/// </summary>
		/// <remarks>Since this is symmetric operation, it doesn't really matter if you use Encrypt or Decrypt method</remarks>
		/// <param name="input">Input byte array</param>
		/// <returns>Byte array that contains decrypted bytes</returns>
		public byte[] DecryptBytes(ReadOnlySpan<byte> input)
		{
			byte[] returnArray = new byte[input.Length];
			this.WorkBytes(returnArray, input);
			return returnArray;
		}

		/// <summary>
		/// Decrypt UTF8 byte array to string.
		/// </summary>
		/// <remarks>Here you can NOT swap encrypt and decrypt methods, because of bytes-string transform</remarks>
		/// <param name="input">Byte array</param>
		/// <returns>Byte array that contains encrypted bytes</returns>
		public string DecryptUtf8ByteArray(Span<byte> input)
		{
			byte[] tempArray = new byte[input.Length];

			this.WorkBytes(tempArray, input);
			return System.Text.Encoding.UTF8.GetString(tempArray);
		}

		#endregion // Decrypt

		/// <summary>
		/// Decrypt / Encrypt arbitrary-length byte stream (input), writing the resulting bytes to another stream (output)
		/// </summary>
		/// <param name="output">Output stream</param>
		/// <param name="input">Input stream</param>
		/// <param name="howManyBytesToProcessAtTime">How many bytes to read and write at time, default is 1024</param>
		private void WorkStreams(Stream output, Stream input, int howManyBytesToProcessAtTime = 1024)
		{
			int read;

			byte[] inputBuffer = new byte[howManyBytesToProcessAtTime];
			byte[] outputBuffer = new byte[howManyBytesToProcessAtTime];

			while ((read = input.Read(inputBuffer, 0, howManyBytesToProcessAtTime)) > 0)
			{
				// Encrypt or decrypt
				this.WorkBytes(outputBuffer, inputBuffer.AsSpan()[..read]);

				// Write buffer
				output.Write(outputBuffer, 0, read);
			}
		}

		async private Task WorkStreamsAsync(Stream output, Stream input, int howManyBytesToProcessAtTime = 1024)
		{
			byte[] readBytesBuffer = new byte[howManyBytesToProcessAtTime];
			byte[] writeBytesBuffer = new byte[howManyBytesToProcessAtTime];
			int read = await input.ReadAsync(readBytesBuffer.AsMemory(0, howManyBytesToProcessAtTime));

			while (read > 0)
			{
				// Encrypt or decrypt
				this.WorkBytes(writeBytesBuffer, readBytesBuffer.AsSpan()[..read]);

				// Write
				await output.WriteAsync(writeBytesBuffer.AsMemory(0, read));

				// Read more
				read = await input.ReadAsync(readBytesBuffer.AsMemory(0, howManyBytesToProcessAtTime));
			}		
		}

		private readonly byte[] _scratch = new byte[ALLOWED_COUNTER_LENGTH];
		private void WorkBytes(Span<byte> output, ReadOnlySpan<byte> input)
		{
			// Check parameters
			if (input == null)
			{
				throw new ArgumentNullException(nameof(input), "Input cannot be null");
			}

			if (output == null)
			{
				throw new ArgumentNullException(nameof(output), "Output cannot be null");
			}

			if (this._isDisposed) 
			{
				throw new ObjectDisposedException("state", "AES_CTR has already been disposed");
			}
			
			int offset = 0;

			int numBytes = input.Length;
			while (numBytes > 0)
			{
				// Generate new XOR mask for next processBytesAtTime
				this._counterEncryptor.TransformBlock(this._counter, 0, ALLOWED_COUNTER_LENGTH, this._scratch, 0);

				// Increase counter (basically this increases the last index first and continues to one before that if 255 -> 0, better solution would be to use uint128, but it does not exist yet)
				if (this._isLittleEndian)
				{
					// LittleEndian
					for (int i = 0; i < ALLOWED_COUNTER_LENGTH; i++)
					{
						if (++this._counter[i] != 0)
						{
							break;
						}
					}
				}
				else
				{
					// BigEndian
					for (int i = ALLOWED_COUNTER_LENGTH - 1; i >= 0; i--)
					{
						if (++this._counter[i] != 0)
						{
							break;
						}
					}
				}

				// Last bytes
				if (numBytes <= PROCESS_BYTES_AT_TIME) 
				{
					for (int i = 0; i < numBytes; i++) 
					{
						output[i + offset] = (byte) (input[i + offset] ^ this._scratch[i]);
					}
					return;
				}

				for (int i = 0; i < PROCESS_BYTES_AT_TIME; i++) 
				{
					output[i + offset] = (byte) (input[i + offset] ^ this._scratch[i]);
				}

				numBytes -= PROCESS_BYTES_AT_TIME;
				offset += PROCESS_BYTES_AT_TIME;
			}
		}


		#region Destructor and Disposer

		/// <summary>
		/// Clear and dispose of the internal variables. The finalizer is only called if Dispose() was never called on this cipher.
		/// </summary>
		~AesCtr() 
		{
			Dispose(false);
		}

		/// <summary>
		/// Clear and dispose of the internal state. Also request the GC not to call the finalizer, because all cleanup has been taken care of.
		/// </summary>
		public void Dispose() 
		{
			Dispose(true);
			/*
			 * The Garbage Collector does not need to invoke the finalizer because Dispose(bool) has already done all the cleanup needed.
			 */
			GC.SuppressFinalize(this);
		}

		/// <summary>
		/// This method should only be invoked from Dispose() or the finalizer. This handles the actual cleanup of the resources.
		/// </summary>
		/// <param name="disposing">
		/// Should be true if called by Dispose(); false if called by the finalizer
		/// </param>
		private void Dispose(bool disposing) 
		{
			if (!this._isDisposed) 
			{
				if (disposing) 
				{
					/* Cleanup managed objects by calling their Dispose() methods */
					if (this._counterEncryptor != null)
					{
						this._counterEncryptor.Dispose();
					}
				}

				/* Cleanup here */
				Array.Clear(this._counter, 0, ALLOWED_COUNTER_LENGTH);	
			}

			this._isDisposed = true;
		}

		#endregion // Destructor and Disposer
	}
}
