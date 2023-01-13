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
