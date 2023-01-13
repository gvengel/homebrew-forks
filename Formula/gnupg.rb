class Gnupg < Formula
  desc "GNU Pretty Good Privacy (PGP) package"
  homepage "https://gnupg.org/"
  url "https://gnupg.org/ftp/gcrypt/gnupg/gnupg-2.3.8.tar.bz2"
  sha256 "540b7a40e57da261fb10ef521a282e0021532a80fd023e75fb71757e8a4969ed"
  license "GPL-3.0-or-later"

  livecheck do
    url "https://gnupg.org/ftp/gcrypt/gnupg/"
    regex(/href=.*?gnupg[._-]v?(\d+(?:\.\d+)+)\.t/i)
  end

  bottle do
    sha256 arm64_ventura:  "6969503746990439b1bee07939dd9558aa41e9360b91173f30d8b53814bdeb87"
    sha256 arm64_monterey: "2097638d35ed8dbdb83634dc720880ec618dbf76e89fdbc28c46b6c3e7ba9998"
    sha256 arm64_big_sur:  "9f82c84919455dde032dc667a76ada4a443d22ad8309fd7d8fdbb3c36ee06515"
    sha256 ventura:        "441995baa0a9064600e0960e4ec1f77a4b7e8b96d83a4353941bfa6212f2ac04"
    sha256 monterey:       "46476571803c002aa14d7f8725db0bbc19784a253cf0498fee8c72966b032806"
    sha256 big_sur:        "1a727ceaf45887631eaaa4aa1a20c5c906e145ed8e0b145607452fe47a98dfb4"
    sha256 catalina:       "e82c083cee3b8c1bc5d9eddbd96ff1759f86b4190acd818b43db435304a03b01"
    sha256 x86_64_linux:   "c7b4f95f9dae0dcc96134a77a7272636ca4a21e4175dc6e5862109ff3bca2c8e"
  end

  depends_on "pkg-config" => :build
  depends_on "gettext"
  depends_on "gnutls"
  depends_on "libassuan"
  depends_on "libgcrypt"
  depends_on "libgpg-error"
  depends_on "libksba"
  depends_on "libusb"
  depends_on "npth"
  depends_on "pinentry"

  uses_from_macos "sqlite", since: :catalina

  on_linux do
    depends_on "libidn"
  end

  # Fixes a build failure without ldap.
  # Committed upstream, will be in the next release.
  # https://dev.gnupg.org/T6239
  patch do
    url "https://dev.gnupg.org/rG7011286ce6e1fb56c2989fdafbd11b931c489faa?diff=1"
    sha256 "407011d4ae9799f50008b431df60cd5b781dca0f572e956fd46245aa209af7e8"
  end

  patch :DATA

  def install
    libusb = Formula["libusb"]
    ENV.append "CPPFLAGS", "-I#{libusb.opt_include}/libusb-#{libusb.version.major_minor}"

    system "./configure", "--disable-dependency-tracking",
                          "--disable-silent-rules",
                          "--prefix=#{prefix}",
                          "--sbindir=#{bin}",
                          "--sysconfdir=#{etc}",
                          "--enable-all-tests",
                          "--with-pinentry-pgm=#{Formula["pinentry"].opt_bin}/pinentry"
    system "make"
    system "make", "check"
    system "make", "install"

    # Configure scdaemon as recommended by upstream developers
    # https://dev.gnupg.org/T5415#145864
    if OS.mac?
      # write to buildpath then install to ensure existing files are not clobbered
      (buildpath/"scdaemon.conf").write <<~EOS
        disable-ccid
      EOS
      pkgetc.install "scdaemon.conf"
    end
  end

  def post_install
    (var/"run").mkpath
    quiet_system "killall", "gpg-agent"
  end

  test do
    (testpath/"batch.gpg").write <<~EOS
      Key-Type: RSA
      Key-Length: 2048
      Subkey-Type: RSA
      Subkey-Length: 2048
      Name-Real: Testing
      Name-Email: testing@foo.bar
      Expire-Date: 1d
      %no-protection
      %commit
    EOS
    begin
      system bin/"gpg", "--batch", "--gen-key", "batch.gpg"
      (testpath/"test.txt").write "Hello World!"
      system bin/"gpg", "--detach-sign", "test.txt"
      system bin/"gpg", "--verify", "test.txt.sig"
    ensure
      system bin/"gpgconf", "--kill", "gpg-agent"
    end
  end
end

__END__
diff --git a/scd/app-openpgp.c b/scd/app-openpgp.c
index e445b24..f3286d3 100644
--- a/scd/app-openpgp.c
+++ b/scd/app-openpgp.c
@@ -5361,6 +5361,9 @@ do_sign (app_t app, ctrl_t ctrl, const char *keyidstr, int hashalgo,
       wipe_and_free (pinvalue, pinlen);
     }
 
+  // Prompt to touch/ack the card.
+  if (opt.ack_prompt)
+    pincb (pincb_arg, _("--ack"), NULL);
 
   if (app->app_local->cardcap.ext_lc_le
       && app->app_local->keyattr[0].key_type == KEY_TYPE_RSA
@@ -5384,6 +5387,10 @@ do_sign (app_t app, ctrl_t ctrl, const char *keyidstr, int hashalgo,
       cache_pin (app, ctrl, 1, NULL);
     }
 
+  // Dismiss prompt after signing (or timing out)
+  if (opt.ack_prompt)
+    pincb (pincb_arg, NULL, NULL);
+
   return rc;
 }
 
@@ -5546,9 +5553,19 @@ do_auth (app_t app, ctrl_t ctrl, const char *keyidstr,
           exmode = 0;
           le_value = 0;
         }
+
+      // Prompt to touch/ack the card.
+      if (opt.ack_prompt)
+        pincb (pincb_arg, _("--ack"), NULL);
+
       rc = iso7816_internal_authenticate (app_get_slot (app), exmode,
                                           indata, indatalen, le_value,
                                           outdata, outdatalen);
+
+      // Dismiss prompt after authenticating (or timing out)
+      if (opt.ack_prompt)
+        pincb (pincb_arg, NULL, NULL);
+
       if (gpg_err_code (rc) == GPG_ERR_TIMEOUT)
         clear_chv_status (app, ctrl, 1);
 
@@ -5830,10 +5847,20 @@ do_decipher (app_t app, ctrl_t ctrl, const char *keyidstr,
   else
     exmode = le_value = 0;
 
+  // Prompt to touch/ack the card.
+  if (opt.ack_prompt)
+    pincb (pincb_arg, _("--ack"), NULL);
+
   rc = iso7816_decipher (app_get_slot (app), exmode,
                          indata, indatalen, le_value, padind,
                          outdata, outdatalen);
   xfree (fixbuf);
+
+  // Dismiss prompt after deciphering (or timing out)
+  if (opt.ack_prompt)
+    pincb (pincb_arg, NULL, NULL);
+
+
   if (!rc && app->app_local->keyattr[1].key_type == KEY_TYPE_ECC)
     {
       unsigned char prefix = 0;
diff --git a/scd/scdaemon.c b/scd/scdaemon.c
index e43769f..b12540c 100644
--- a/scd/scdaemon.c
+++ b/scd/scdaemon.c
@@ -102,6 +102,7 @@ enum cmd_and_opt_values
   oDenyAdmin,
   oDisableApplication,
   oApplicationPriority,
+  oAckPrompt,
   oEnablePinpadVarlen,
   oListenBacklog
 };
@@ -170,6 +171,7 @@ static gpgrt_opt_t opts[] = {
   ARGPARSE_s_s (oDisableApplication, "disable-application", "@"),
   ARGPARSE_s_s (oApplicationPriority, "application-priority",
                 N_("|LIST|change the application priority to LIST")),
+  ARGPARSE_s_n (oAckPrompt, "ack-prompt", N_("display ACK prompt while waiting for card")),
   ARGPARSE_s_i (oListenBacklog, "listen-backlog", "@"),
 
 
@@ -611,6 +613,8 @@ main (int argc, char **argv )
 
         case oDisablePinpad: opt.disable_pinpad = 1; break;
 
+        case oAckPrompt: opt.ack_prompt = 1; break;
+
         case oAllowAdmin: /* Dummy because allow is now the default.  */
           break;
         case oDenyAdmin: opt.allow_admin = 0; break;
diff --git a/scd/scdaemon.h b/scd/scdaemon.h
index 68136b8..5a63e24 100644
--- a/scd/scdaemon.h
+++ b/scd/scdaemon.h
@@ -60,6 +60,7 @@ struct
   int disable_ccid;    /* Disable the use of the internal CCID driver. */
   int disable_pinpad;  /* Do not use a pinpad. */
   int enable_pinpad_varlen;  /* Use variable length input for pinpad. */
+  int ack_prompt;      /* Display ACK prompt to user when waiting for card. */
   int allow_admin;     /* Allow the use of admin commands for certain
                           cards. */
   int pcsc_shared;     /* Use shared PC/SC access.  */
