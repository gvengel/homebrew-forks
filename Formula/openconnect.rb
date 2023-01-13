class Openconnect < Formula
  desc "Open client for Cisco AnyConnect VPN"
  homepage "https://www.infradead.org/openconnect/"
  url "ftp://ftp.infradead.org/pub/openconnect/openconnect-9.01.tar.gz"
  mirror "https://fossies.org/linux/privat/openconnect-9.01.tar.gz"
  sha256 "b3d7faf830e9793299d6a41e81d84cd4a3e2789c148c9e598e4585010090e4c7"
  license "LGPL-2.1-only"
  revision 2

  livecheck do
    url "https://www.infradead.org/openconnect/download.html"
    regex(/href=.*?openconnect[._-]v?(\d+(?:\.\d+)+)\.t/i)
  end

  bottle do
    sha256 arm64_monterey: "6dc4bcb064f2682ec83df05e98ebdc4c01bb393311ecc4d60f70574ac5dc6091"
    sha256 arm64_big_sur:  "2eeb96ab48ce2e23288d738575415a9cca7356d2ef82f6dbe5c076ba85242422"
    sha256 monterey:       "a5cada9bca9cc64b03ee450d06d4064edc2a55896c4b5518b558aaa68ea86b04"
    sha256 big_sur:        "cdcbb4640fee08eb17685920cc0af6d5c74989296d222c6f21c6b51a49f319bf"
    sha256 catalina:       "4653dc9700dc255351900b68baa48c3da01eabe5b83a42384744f825bd4a13a3"
    sha256 x86_64_linux:   "2f6ef9a3246f5bb6e134c50e68d45c9515b7d5529be624dcfb9b4b261b6a5e4b"
  end

  head do
    url "git://git.infradead.org/users/dwmw2/openconnect.git", branch: "master"

    depends_on "autoconf" => :build
    depends_on "automake" => :build
    depends_on "libtool" => :build
  end

  depends_on "pkg-config" => :build
  depends_on "gettext"
  depends_on "gnutls"
  depends_on "stoken"

  resource "vpnc-script" do
    url "https://gitlab.com/openconnect/vpnc-scripts/raw/e52f8e66391c4c55ee818841d236ebbb6ae284ed/vpnc-script"
    sha256 "6d95e3625cceb51e77628196055adb58c3e8325b9f66fcc8e97269caf42b8575"
  end

  patch :DATA

  def install
    (etc/"vpnc").install resource("vpnc-script")
    chmod 0755, etc/"vpnc/vpnc-script"

    if build.head?
      ENV["LIBTOOLIZE"] = "glibtoolize"
      system "./autogen.sh"
    end

    args = %W[
      --prefix=#{prefix}
      --sbindir=#{bin}
      --localstatedir=#{var}
      --with-vpnc-script=#{etc}/vpnc/vpnc-script
    ]

    system "./configure", *args
    system "make", "install"
  end

  def caveats
    s = <<~EOS
      A `vpnc-script` has been installed at #{etc}/vpnc/vpnc-script.
    EOS

    s += if (etc/"vpnc/vpnc-script.default").exist?
      <<~EOS

        To avoid destroying any local changes you have made, a newer version of this script has
        been installed as `vpnc-script.default`.
      EOS
    end.to_s

    s
  end

  test do
    # We need to pipe an empty string to `openconnect` for this test to work.
    assert_match "POST https://localhost/", pipe_output("#{bin}/openconnect localhost 2>&1", "")
  end
end

__END__
diff --git a/pulse.c b/pulse.c
index 3822e6a8..ba475050 100644
--- a/pulse.c
+++ b/pulse.c
@@ -2311,20 +2311,25 @@ static int handle_main_config_packet(struct openconnect_info *vpninfo,
 	 *     00 0d           (length 13)
 	 *     03 00 00 00     (fixed)
 	 *     40 25 00 01 01  (unknown attr 0x4025, length 1, value 0x01)
+	 * Pulse 9.1R16: skip over a list of such attributes, ending with a 0x2c0
 	*/
 	if (bytes[0x20] == 0x2e) {
 		/* Length of attributes section */
-		int attr_len = load_be16(bytes + 0x2e);
-
-		/* Start of attributes */
-		if (load_be16(bytes + 0x2c) != 0x2c00 ||
-		    len < 0x2c + attr_len + 4 ||
-		    /* Process the attributes */
-		    handle_attr_elements(vpninfo, bytes + 0x2c, attr_len,
-					 &new_opts, &new_ip_info) < 0) {
-			goto bad_config;
-		}
-		offset += attr_len;
+		int attr_flag;
+		int attr_len;
+		do {
+			/* Start of attributes */
+			attr_flag = load_be16(bytes + offset);
+			attr_len = load_be16(bytes+offset+2);
+			if ( (attr_flag != 0x2c00 && attr_flag != 0x2e00) ||
+				len < offset + attr_len + 4 ||
+				/* Process the attributes */
+				handle_attr_elements(vpninfo, bytes + offset, attr_len,
+									 &new_opts, &new_ip_info) < 0) {
+					goto bad_config;
+			}
+			offset += attr_len;
+		} while (attr_flag != 0x2c00);
 	}
 
 	/* First part of header, similar to ESP, has already been checked */
