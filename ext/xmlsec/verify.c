#include <xmlsec_ext.h>
#include <verify.h>
#include <errno.h>

extern VALUE mXmlSec, cXmlSecError;

VALUE xmlsec_is_valid_by_x509_file(VALUE self, xmlDocPtr doc, VALUE x509_file ) {
  xmlSecKeysMngrPtr mngr;
  xmlNodePtr node = NULL;
  xmlSecDSigCtxPtr dsigCtx = NULL;

  mngr = xmlSecKeysMngrCreate();

  if(mngr == NULL) {
    if(doc != NULL) xmlFreeDoc(doc);
    rb_raise(rb_eRuntimeError, "Error: failed to create keys manager.\n");
    return Qnil;
  }

  if(xmlSecCryptoAppDefaultKeysMngrInit(mngr) < 0) {
    if(doc != NULL) xmlFreeDoc(doc);
    if(mngr != NULL) xmlSecKeysMngrDestroy(mngr);
    rb_raise(rb_eRuntimeError, "Error: failed to initialize keys manager.\n");
    return Qnil;
  }

  /* load trusted cert */
  if(xmlSecCryptoAppKeysMngrCertLoad(mngr, StringValuePtr(x509_file), xmlSecKeyDataFormatPem, xmlSecKeyDataTypeTrusted) < 0) {
    if(doc != NULL) xmlFreeDoc(doc);
    if(mngr != NULL) xmlSecKeysMngrDestroy(mngr);
    rb_raise(rb_eRuntimeError, "Error: failed to load pem certificate from \"%s\"\n", StringValuePtr(x509_file));
    return Qnil;
  }

  /* find start node */
  node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
  if(node == NULL) {
    if(doc != NULL) xmlFreeDoc(doc);
    rb_raise(rb_eRuntimeError, "Error: start node not found\n");
    return Qnil;
  }

  /* create signature context*/
  dsigCtx = xmlSecDSigCtxCreate(mngr);
  if(dsigCtx == NULL) {
    if(doc != NULL) xmlFreeDoc(doc);
    if(mngr != NULL) xmlSecKeysMngrDestroy(mngr);
    rb_raise(rb_eRuntimeError, "Error: failed to create signature context\n");
    return Qnil;
  }

  /* Verify signature */
  if(xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
    if(dsigCtx != NULL) xmlSecDSigCtxDestroy(dsigCtx);
    if(doc != NULL) xmlFreeDoc(doc);
    if(mngr != NULL) xmlSecKeysMngrDestroy(mngr);
    rb_raise(rb_eRuntimeError, "Error: signature verify \"%s\"\n");
    return Qnil;
  }

  /* verification result*/
  if(dsigCtx->status == xmlSecDSigStatusSucceeded) {
    if(dsigCtx != NULL) xmlSecDSigCtxDestroy(dsigCtx);
    if(doc != NULL) xmlFreeDoc(doc);
    if(mngr != NULL) xmlSecKeysMngrDestroy(mngr);
    return Qtrue;
  } else {
    if(dsigCtx != NULL) xmlSecDSigCtxDestroy(dsigCtx);
    if(doc != NULL) xmlFreeDoc(doc);
    if(mngr != NULL) xmlSecKeysMngrDestroy(mngr);
    return Qfalse;
  }

}

VALUE xmlsec_is_valid(VALUE self, xmlDocPtr doc) {
  xmlNodePtr node = NULL;
  xmlSecDSigCtxPtr dsigCtx = NULL;

  /* find start node */
  node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
  if(node == NULL) {
    if(doc != NULL) xmlFreeDoc(doc);
    rb_raise(rb_eRuntimeError, "Error: start node not found\n");
    return Qnil;
  }

  /* create signature context*/
  dsigCtx = xmlSecDSigCtxCreate(NULL);
  if(dsigCtx == NULL) {
    if(doc != NULL) xmlFreeDoc(doc);
    rb_raise(rb_eRuntimeError, "Error: failed to create signature context\n");
    return Qnil;
  }

  /* Verify signature */
  if(xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
    if(dsigCtx != NULL) xmlSecDSigCtxDestroy(dsigCtx);
    if(doc != NULL) xmlFreeDoc(doc);
    rb_raise(rb_eRuntimeError, "Error: signature verify \"%s\"\n");
    return Qnil;
  }

  /* verification result*/
  if(dsigCtx->status == xmlSecDSigStatusSucceeded) {
    if(dsigCtx != NULL) xmlSecDSigCtxDestroy(dsigCtx);
    if(doc != NULL) xmlFreeDoc(doc);
    return Qtrue;
  } else {
    if(dsigCtx != NULL) xmlSecDSigCtxDestroy(dsigCtx);
    if(doc != NULL) xmlFreeDoc(doc);
    return Qfalse;
  }

}

VALUE xmlsec_is_valid_by_key(VALUE self, xmlDocPtr doc, VALUE key_file ) {
  xmlNodePtr node = NULL;
  xmlSecDSigCtxPtr dsigCtx = NULL;

  /* find start node */
  node = xmlSecFindNode(xmlDocGetRootElement(doc), xmlSecNodeSignature, xmlSecDSigNs);
  if(node == NULL) {
    if(doc != NULL) xmlFreeDoc(doc);
    rb_raise(rb_eRuntimeError, "Error: start node not found\n");
    return Qnil;
  }

  /* create signature context*/
  dsigCtx = xmlSecDSigCtxCreate(NULL);
  if(dsigCtx == NULL) {
    if(doc != NULL) xmlFreeDoc(doc);
    rb_raise(rb_eRuntimeError, "Error: failed to create signature context\n");
    return Qnil;
  }

  /* load public key */
  dsigCtx->signKey = xmlSecCryptoAppKeyLoad(StringValuePtr(key_file), xmlSecKeyDataFormatPem, NULL, NULL, NULL);
  if(dsigCtx->signKey == NULL) {
    if(dsigCtx != NULL) xmlSecDSigCtxDestroy(dsigCtx);
    if(doc != NULL) xmlFreeDoc(doc);
    rb_raise(rb_eRuntimeError, "Error: failed to load public pem key from \"%s\"\n", StringValuePtr(key_file));
    return Qnil;
  }

  /* set key name to the file name*/
  if(xmlSecKeySetName(dsigCtx->signKey, StringValuePtr(key_file)) < 0) {
    if(dsigCtx != NULL) xmlSecDSigCtxDestroy(dsigCtx);
    if(doc != NULL) xmlFreeDoc(doc);
    rb_raise(rb_eRuntimeError, "Error: failed to set key name for key from \"%s\"\n", StringValuePtr(key_file));
    return Qnil;
  }

  /* Verify signature */
  if(xmlSecDSigCtxVerify(dsigCtx, node) < 0) {
    if(dsigCtx != NULL) xmlSecDSigCtxDestroy(dsigCtx);
    if(doc != NULL) xmlFreeDoc(doc);
    rb_raise(rb_eRuntimeError, "Error: signature verify \"%s\"\n");
    return Qnil;
  }

  /* verification result*/
  if(dsigCtx->status == xmlSecDSigStatusSucceeded) {
    if(dsigCtx != NULL) xmlSecDSigCtxDestroy(dsigCtx);
    if(doc != NULL) xmlFreeDoc(doc);
    return Qtrue;
  } else {
    if(dsigCtx != NULL) xmlSecDSigCtxDestroy(dsigCtx);
    if(doc != NULL) xmlFreeDoc(doc);
    return Qfalse;
  }
}

static VALUE rb_xmlsec_is_valid_file(VALUE self, VALUE template_file, VALUE key_file, VALUE x509_file ) {
  xmlDocPtr doc;

  doc = xmlParseFile(StringValuePtr(template_file));

  if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)) {
    rb_raise(rb_eRuntimeError, "Error: unable to parse  template file.");
    return Qnil;
  }
  if (! NIL_P(x509_file)) return xmlsec_is_valid_by_x509_file(self, doc, x509_file );
  if (! NIL_P(key_file)) return xmlsec_is_valid_by_key(self, doc, key_file);
  return xmlsec_is_valid(self, doc);
}

static VALUE rb_xmlsec_is_valid(VALUE self, VALUE template, VALUE key_file, VALUE x509_file ) {
  xmlDocPtr doc;
  doc = xmlReadMemory(
      StringValuePtr(template),
      RSTRING_LEN(template),
      "noname.xml",
      NULL,
      0
    );
  if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)){
    rb_raise(rb_eRuntimeError, "Error: unable to parse  template.");
    return Qnil;
  }
  if (! NIL_P(x509_file)) return xmlsec_is_valid_by_x509_file(self, doc, x509_file );
  if (! NIL_P(key_file)) return xmlsec_is_valid_by_key(self, doc, key_file);
  return xmlsec_is_valid(self, doc);
}


void init_xmlsec_verify(){

  rb_define_singleton_method(mXmlSec, "valid_file?", rb_xmlsec_is_valid_file, 3);
  rb_define_singleton_method(mXmlSec, "valid?", rb_xmlsec_is_valid, 3);

}
