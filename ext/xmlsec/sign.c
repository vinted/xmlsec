#include <xmlsec_ext.h>
#include <sign.h>
#include <errno.h>


extern VALUE mXmlSec, cXmlSecError;

static VALUE xmlsec_sign(VALUE self, xmlDocPtr doc, VALUE key_file, VALUE password, VALUE x509_file, VALUE node_name ) {

  xmlNodePtr signNode = NULL;
  xmlNodePtr refNode = NULL;
  xmlNodePtr pathNode = NULL;
  xmlNodePtr keyInfoNode = NULL;
  xmlSecDSigCtxPtr dsigCtx = NULL;
  xmlChar *xmlbuff;
  int xmlbuffsize;
  VALUE result;


  /* create signature template for RSA-SHA1 enveloped signature */
  signNode = xmlSecTmplSignatureCreate( doc,
                                        xmlSecTransformExclC14NWithCommentsId,
                                        xmlSecTransformRsaSha1Id,
                                       NULL
                                      );
  if(signNode == NULL) {
    if(doc != NULL) xmlFreeDoc(doc);
    rb_raise(rb_eRuntimeError, "Error: failed to create signature template\n");
    return Qnil;
  }

  pathNode =  xmlDocGetRootElement(doc);
  if (! NIL_P(node_name)) {
    pathNode = xmlNewChild(xmlDocGetRootElement(doc), NULL, StringValuePtr(node_name), NULL);
    if(pathNode == NULL) {
      if(doc != NULL) xmlFreeDoc(doc);
      rb_raise(rb_eRuntimeError, "Error: failed to create %s node\n", StringValuePtr(node_name));
      return Qnil;
    }
  }

  /* add <dsig:Signature/> node to the doc */
  xmlAddChild(pathNode, signNode);

  /* add reference */
  refNode = xmlSecTmplSignatureAddReference(signNode,
                                            xmlSecTransformSha1Id,
                                            NULL,
                                            NULL,
                                            NULL);
  if(refNode == NULL) {
    if(doc != NULL) xmlFreeDoc(doc);
    rb_raise(rb_eRuntimeError, "Error: failed to add reference to signature template\n");
    return Qnil;
  }

  /* add enveloped transform */
  if(xmlSecTmplReferenceAddTransform(refNode, xmlSecTransformEnvelopedId) == NULL) {
    if(doc != NULL) xmlFreeDoc(doc);
    rb_raise(rb_eRuntimeError, "Error: failed to add enveloped transform to reference\n");
    return Qnil;
  }

  if (! NIL_P(x509_file)){

    /* add <dsig:KeyInfo/> and <dsig:X509Data/> */
    keyInfoNode = xmlSecTmplSignatureEnsureKeyInfo(signNode, NULL);
    if(keyInfoNode == NULL) {
      if(doc != NULL) xmlFreeDoc(doc);
      rb_raise(rb_eRuntimeError, "Error: failed to add key info\n");
      return Qnil;
    }

    if(xmlSecTmplKeyInfoAddX509Data(keyInfoNode) == NULL) {
      if(doc != NULL) xmlFreeDoc(doc);
      rb_raise(rb_eRuntimeError, "Error: failed to add X509Data node\n");
      return Qnil;
    }
  }

  /* create signature context, we don't need keys manager in this example */
  dsigCtx = xmlSecDSigCtxCreate(NULL);
  if(dsigCtx == NULL) {
    if(doc != NULL) xmlFreeDoc(doc);
    rb_raise(rb_eRuntimeError, "Error: failed to create signature context\n");
    return Qnil;
  }

  /* load private key, assuming that there is not password */
  dsigCtx->signKey = xmlSecCryptoAppKeyLoad(StringValuePtr(key_file),
                                            xmlSecKeyDataFormatPem,
                                            NIL_P(password) ? NULL : StringValuePtr(password),
                                            NULL,
                                            NULL);

  if(dsigCtx->signKey == NULL) {
      if(dsigCtx != NULL) xmlSecDSigCtxDestroy(dsigCtx);
      if(doc != NULL) xmlFreeDoc(doc);
      rb_raise(rb_eRuntimeError, "Error: failed to load private pem key from \"%s\"\n", StringValuePtr(key_file));
      return Qnil;
  }

  if (! NIL_P(x509_file)){
    /* load certificate and add to the key */
    if(xmlSecCryptoAppKeyCertLoad(dsigCtx->signKey, StringValuePtr(x509_file), xmlSecKeyDataFormatPem) < 0) {
      if(dsigCtx != NULL) xmlSecDSigCtxDestroy(dsigCtx);
      if(doc != NULL) xmlFreeDoc(doc);
      rb_raise(rb_eRuntimeError, "Error: failed to load pem certificate \"%s\"\n", StringValuePtr(x509_file));
      return Qnil;
    }
  }

    /* set key name to the file name, this is just an example! */
    if(xmlSecKeySetName(dsigCtx->signKey, StringValuePtr(key_file)) < 0) {
      if(dsigCtx != NULL) xmlSecDSigCtxDestroy(dsigCtx);
      if(doc != NULL) xmlFreeDoc(doc);
      rb_raise(rb_eRuntimeError, "Error: failed to set key name for key from \"%s\"\n", StringValuePtr(key_file));
      return Qnil;
    }

    /* sign the template */
    if(xmlSecDSigCtxSign(dsigCtx, signNode) < 0) {
      if(dsigCtx != NULL) xmlSecDSigCtxDestroy(dsigCtx);
      if(doc != NULL) xmlFreeDoc(doc);
      rb_raise(rb_eRuntimeError, "Error: signature failed");
      return Qnil;
    }

    /* return signed document*/
    xmlDocDumpFormatMemory(doc, &xmlbuff, &xmlbuffsize, 1);
    result =  rb_str_new(xmlbuff, xmlbuffsize);
    xmlFree(xmlbuff);
    if(dsigCtx != NULL) xmlSecDSigCtxDestroy(dsigCtx);
    if(doc != NULL) xmlFreeDoc(doc);
    return result;

}

static VALUE rb_xmlsec_sign_file(VALUE self, VALUE template_file, VALUE key_file, VALUE password, VALUE x509_file, VALUE node_name) {
  xmlDocPtr doc;

  doc = xmlParseFile(StringValuePtr(template_file));

  if ((doc == NULL) || (xmlDocGetRootElement(doc) == NULL)) {
    rb_raise(rb_eRuntimeError, "Error: unable to parse  template file.");
    return;
  }

  return xmlsec_sign(self, doc, key_file, password, x509_file, node_name );
}

static VALUE rb_xmlsec_sign(VALUE self, VALUE template, VALUE key_file, VALUE password, VALUE x509_file, VALUE node_name ) {
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
    return;
  }
  return xmlsec_sign(self, doc, key_file, password, x509_file,node_name );
}


void init_xmlsec_sign() {

  rb_define_singleton_method(mXmlSec, "sign_file", rb_xmlsec_sign_file, 5);
  rb_define_singleton_method(mXmlSec, "sign", rb_xmlsec_sign, 5);

}