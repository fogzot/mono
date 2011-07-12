//
// CryptoConfig.cs: Handles cryptographic implementations and OIDs mappings.
//
// Author:
//	Sebastien Pouliot (sebastien@ximian.com)
//	Tim Coleman (tim@timcoleman.com)
//
// (C) 2002, 2003 Motus Technologies Inc. (http://www.motus.com)
// Copyright (C) Tim Coleman, 2004
// Copyright (C) 2004-2007, 2009 Novell, Inc (http://www.novell.com)
//
// Permission is hereby granted, free of charge, to any person obtaining
// a copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to
// permit persons to whom the Software is furnished to do so, subject to
// the following conditions:
// 
// The above copyright notice and this permission notice shall be
// included in all copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
// EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
// NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
// LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
// OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//

namespace System.Security.Cryptography {

	public partial class CryptoConfig {

		public static byte[] EncodeOID (string str)
		{
			return CryptoConfigHelper.EncodeOID (str);
		}

#if MOONLIGHT
		// we need SHA1 support to verify the codecs binary integrity
		public static string MapNameToOID (string name)
		{
			if ((name != null) && name.Contains ("SHA1"))
				return "1.3.14.3.2.26";
			return String.Empty;
		}

		private const string AES = "System.Security.Cryptography.AesManaged, System.Core, Version=2.0.5.0, Culture=neutral, PublicKeyToken=b77a5c561934e089";

		// non-configurable (versus machine.config) mappings for Moonlight (to avoid loading custom code)
		public static object CreateFromName (string name)
		{
			switch (name) {
			case "System.Security.Cryptography.HashAlgorithm":
			case "System.Security.Cryptography.SHA1":
			case "SHA1":
				return new SHA1Managed ();
			case "SHA256":
				return new SHA256Managed ();
			case "System.Security.Cryptography.MD5":
			case "MD5":
				return new MD5CryptoServiceProvider ();
			case "System.Security.Cryptography.RandomNumberGenerator":
				return new RNGCryptoServiceProvider ();
			case "System.Security.Cryptography.RSA":
				return new Mono.Security.Cryptography.RSAManaged ();
			case "AES":
			case AES:
				return (Aes) Activator.CreateInstance (Type.GetType (AES), null);
			default:
				throw new NotImplementedException (name);
			}
		}
#endif
	}
}

