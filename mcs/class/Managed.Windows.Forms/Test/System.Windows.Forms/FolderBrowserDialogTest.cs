//
// FolderBrowserDialogTest.cs: Test cases for FolderBrowserDialog.
//
// Author:
//	Gert Driesen (drieseng@users.sourceforge.net)
//
// (C) 2007 Gert Driesen
//

using System;
using System.ComponentModel;
using System.Windows.Forms;

using NUnit.Framework;

namespace MonoTests.System.Windows.Forms
{
	[TestFixture]
	public class FolderBrowserDialogTest
	{
		[Test]
		public void SelectedPath ()
		{
			FolderBrowserDialog fbd = new FolderBrowserDialog ();
			Assert.AreEqual (string.Empty, fbd.SelectedPath, "#1");
			fbd.SelectedPath = null;
			Assert.AreEqual (string.Empty, fbd.SelectedPath, "#2");
			fbd.SelectedPath = "{}###()";
			Assert.AreEqual ("{}###()", fbd.SelectedPath, "#3");
		}

		[Test]
		public void RootFolder ()
		{
			FolderBrowserDialog fbd = new FolderBrowserDialog ();
			Assert.AreEqual (Environment.SpecialFolder.Desktop, fbd.RootFolder, "#1");
			fbd.RootFolder = Environment.SpecialFolder.Personal;
			Assert.AreEqual (Environment.SpecialFolder.Personal, fbd.RootFolder, "#2");
		}

		[Test]
		public void RootFolder_Invalid ()
		{
			FolderBrowserDialog fbd = new FolderBrowserDialog ();
			try {
				fbd.RootFolder = (Environment.SpecialFolder) 666;
				Assert.Fail ("#1");
			} catch (InvalidEnumArgumentException ex) {
				Assert.AreEqual (typeof (InvalidEnumArgumentException), ex.GetType (), "#2");
				Assert.IsNull (ex.InnerException, "#3");
				Assert.IsNotNull (ex.Message, "#4");
				Assert.IsTrue (ex.Message.IndexOf ("666") != -1, "#5");
				Assert.IsTrue (ex.Message.IndexOf ("SpecialFolder") != -1, "#6");
				Assert.IsNotNull (ex.ParamName, "#7");
				Assert.AreEqual ("value", ex.ParamName, "#8");
			}
		}
	}
}
