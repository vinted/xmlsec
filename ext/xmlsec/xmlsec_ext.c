#include <xmlsec_ext.h>

VALUE mXmlSec, cXmlSecError;

/* Ruby Extension initializer */
void Init_xmlsec_ext() {
#ifndef XMLSEC_NO_XSLT
  xsltSecurityPrefsPtr xsltSecPrefs = NULL;
#endif /* XMLSEC_NO_XSLT */

  mXmlSec      = rb_define_module("XmlSec");
  cXmlSecError = rb_const_get(mXmlSec, rb_intern("Error"));

  /* Init libxml and libxslt libraries */
  xmlInitParser();
  LIBXML_TEST_VERSION
  xmlLoadExtDtdDefaultValue = XML_DETECT_IDS | XML_COMPLETE_ATTRS;
  xmlSubstituteEntitiesDefault(1);
#ifndef XMLSEC_NO_XSLT
  xmlIndentTreeOutput = 1;
#endif /* XMLSEC_NO_XSLT */

    /* Init libxslt */
#ifndef XMLSEC_NO_XSLT
  /* disable everything */
  xsltSecPrefs = xsltNewSecurityPrefs();
  xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_FILE,        xsltSecurityForbid);
  xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_FILE,       xsltSecurityForbid);
  xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_CREATE_DIRECTORY, xsltSecurityForbid);
  xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_READ_NETWORK,     xsltSecurityForbid);
  xsltSetSecurityPrefs(xsltSecPrefs,  XSLT_SECPREF_WRITE_NETWORK,    xsltSecurityForbid);
  xsltSetDefaultSecurityPrefs(xsltSecPrefs);
#endif /* XMLSEC_NO_XSLT */

  /* Init xmlsec library */
  if(xmlSecInit() < 0) {
    rb_raise(rb_eRuntimeError, "Error: xmlsec initialization failed.");
    return;
  }

  /* Check loaded library version */
  if(xmlSecCheckVersion() != 1) {
    rb_raise(rb_eRuntimeError, "Error: loaded xmlsec library version is not compatible.");
    return;
  }

/* Load default crypto engine if we are supporting dynamic
 * loading for xmlsec-crypto libraries. Use the crypto library
 * name ("openssl", "nss", etc.) to load corresponding
 * xmlsec-crypto library.
 */
#ifdef XMLSEC_CRYPTO_DYNAMIC_LOADING
  if(xmlSecCryptoDLLoadLibrary(BAD_CAST XMLSEC_CRYPTO) < 0) {
    rb_raise(rb_eRuntimeError, "Error: unable to load default xmlsec-crypto library. Make sure\n"
                      "that you have it installed and check shared libraries path\n"
                      "(LD_LIBRARY_PATH) envornment variable.\n");
    return;
  }
#endif /* XMLSEC_CRYPTO_DYNAMIC_LOADING */

  /* Init crypto library */
  if(xmlSecCryptoAppInit(NULL) < 0) {
    rb_raise(rb_eRuntimeError, "Error: crypto initialization failed.");
    return;
  }

  /* Init xmlsec-crypto library */
  if(xmlSecCryptoInit() < 0) {
    rb_raise(rb_eRuntimeError, "Error: xmlsec-crypto initialization failed.");
    return;
  }

  init_xmlsec_sign();
  init_xmlsec_verify();
}