// in the body of the html page should be
// <object id="cadesplugin" type="application/x-cades" class="hiddenObject"></object>
// {
//   var cp = new CryptoPro(..., ..., onSignFinished);
//   // getting - GET with id parameter
//   // object identifier and signature will be transferred to processUrl in POST-parameters "id" and "sign"
//   var certs = cp.getCerts(); // returns certificate key => text view
//   ... // [show, ] select the certificate
//   cp.makeSign(objId, certKey);
// }
// function onSignFinished(/*string*/ objId, /*string*/ errorMessage) {
//   // errorMessage == null, if there were no errors
// }
// return statuses:
// not ready - not ready (in the process of signing another object)
// receiving - receiving an object
// signing   - signing
// sending   - sending
// success
// fail

function onCadesLoaded(cb) {
  if (typeof cadesplugin === 'undefined') {
    return cb();
  }

  var canPromise = !!window.Promise;
  if(canPromise) {
    cadesplugin.then(cb,
      function(error) {
        console.error(error);
        cb(error);
      }
    );
  } else {
    window.addEventListener("message", function (event){
        if (event.data === "cadesplugin_loaded") {
          cb();
        } else if(event.data === "cadesplugin_load_error") {
          console.error("Plugin CryptoPro not loaded");
          cb("Plugin CryptoPro not loaded");
        }
      },
      false);
    window.postMessage("cadesplugin_echo_request", "*");
  }
}

function CryptoPro() {
	this.state = "ready";
  this.store = null;

	this.CAPICOM_CERTIFICATE_FIND_SHA1_HASH = 0;
	this.CADES_BES = 1;
	// CADESCOM_XML_SIGNATURE_TYPE
	this.CADESCOM_XML_SIGNATURE_TYPE_ENVELOPED = 0; // Emplaced signature
	this.CADESCOM_XML_SIGNATURE_TYPE_ENVELOPING = 1; //  Wrapping signature
	this.CADESCOM_XML_SIGNATURE_TYPE_TEMPLATE = 2; // Signature by pattern

	this.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN = 1;

	this.XML_DSIG_GOST_3410_URL = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102001-gostr3411";
	this.XML_DSIG_GOST_3411_URL = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr3411";

	this.OBJ_CAPI_STORE = "CAPICOM.Store";
	this.OBJ_CADES_CP_SIGNER = "CAdESCOM.CPSigner";
	this.OBJ_CADES_SIGNED_DATA = "CAdESCOM.CadesSignedData";
	this.OBJ_CADES_SIGNED_XML = "CAdESCOM.SignedXML";

  this.CAPICOM_CURRENT_USER_STORE = 2;
  this.CAPICOM_MY_STORE = "My";
  this.CAPICOM_LOCAL_MACHINE_STORE = 1;
  this.CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED = 2;

	this.MS_CANT_FIND_OBJ_OR_PROP = 0x80092004;
}

function formCertInfo(cert) {
  var sn = cert.SubjectName;
  var from = sn.indexOf('CN=');
  if (from >= 0) {
      sn = sn.substring(from + 3, sn.indexOf(',', from));
  } else {
    from = sn.indexOf('O=');
    if (from >= 0) {
      sn = sn.substring(from + 2, sn.indexOf(',', from));
    }
  }
  var org = cert.IssuerName;
  from = org.indexOf('CN=');
  if (from >= 0) {
    org = org.substring(from + 3, org.indexOf(',', from));
  } else {
    from = org.indexOf('O=');
    if (from >= 0) {
      org = org.substring(from + 2, org.indexOf(',', from));
    }
  }
  var name = cert.SubjectName;
  var lastName = '';
  from = name.indexOf('SN=');
  if (from !== -1) {
    lastName = name.substring(from + 3, name.indexOf(',', from));
  }
  var firstName = '';
  from = name.indexOf('G=');
  if (from !== -1) {
    firstName = name.substring(from + 2, name.indexOf(',', from));
  }
  return {
    Serial: cert.SerialNumber,
    Subject: sn,
    Issuer: org,
    ValidSince: cert.ValidFromDate,
    ValidTill: cert.ValidToDate,
    SubjectName: cert.SubjectName,
    IssuerName: cert.IssuerName,
    lastName: lastName,
    firstName: firstName
  };
}

CryptoPro.prototype.open = function (cb) {
  if (typeof cadesplugin === 'undefined') {
    return cb();
  }
  if (typeof cadesplugin.CreateObject === 'function') {
    this.store = cadesplugin.CreateObject(this.OBJ_CAPI_STORE);
    this.store.Open();
    cb();
  } else if (typeof cadesplugin.CreateObjectAsync === 'function') {
    var me = this;
    cadesplugin.async_spawn(function *(args) {
      me.store = yield cadesplugin.CreateObjectAsync(me.OBJ_CAPI_STORE);
      yield me.store.Open();
      cb();
    });
  } else {
    cb(new Error('Could not open certificate store!'));
  }
};

CryptoPro.prototype.close = function (cb) {
  if (typeof cadesplugin === 'undefined') {
    return cb();
  }
  if (typeof cadesplugin.CreateObject === 'function') {
    this.store.Close();
    cb();
  } else if (typeof cadesplugin.CreateObjectAsync === 'function') {
    var me = this;
    cadesplugin.async_spawn(function *(args) {
      yield me.store.Close();
      cb();
    });
  } else {
    cb(new Error('Failed to close the certificate store!'));
  }
};

CryptoPro.prototype.getCerts = function(cb) {
  if (typeof cadesplugin === 'undefined') {
    return cb({});
  }
  var me = this;
  if (typeof cadesplugin.CreateObject === 'function') {
    var result = {};
    var CertificatesObj = this.store.Certificates;
    var Count = CertificatesObj.Count;
    var now = new Date();
    for (var i = 1; i <= Count; i++) {
      var cert = CertificatesObj.Item(i);
      var vtd = new Date(cert.ValidToDate);
      var vfd = new Date(cert.ValidFromDate);
      if (now.getTime() <= vtd.getTime() && now.getTime() >= vfd.getTime()
        && cert.HasPrivateKey()
        && cert.IsValid().Result) {
        result[cert.Thumbprint] = formCertInfo(cert);
      }
    }
    cb(result);
  } else if (typeof cadesplugin.CreateObjectAsync === 'function') {
    var me = this;
    cadesplugin.async_spawn(function *(args) {
        var result = {};
        var CertificatesObj = yield me.store.Certificates;
        var Count = yield CertificatesObj.Count;
        var now = new Date();
        for (var i = 1; i <= Count; i++) {
          var cert = yield CertificatesObj.Item(i);
          var vtd = new Date(yield cert.ValidToDate);
          var vfd = new Date(yield cert.ValidFromDate);
          var hpk = yield cert.HasPrivateKey();
          var iv = yield cert.IsValid();
          iv = yield iv.Result;
          if (now.getTime() <= vtd.getTime() && now.getTime() >= vfd.getTime()
            && hpk
            && iv) {
            var key = yield cert.Thumbprint;
            var sn = yield cert.SubjectName;
            var isn = yield cert.IssuerName;
            var ser = yield cert.SerialNumber;
            result[key] = formCertInfo(
              {
                SubjectName: sn,
                IssuerName: isn,
                SerialNumber: ser,
                ValidFromDate: vfd,
                ValidToDate: vtd
              }
            );
          }
        }
        cb(result);
    });
  } else {
    cb({});
  }
};

CryptoPro.prototype.getSignFunc = function(contentType, onFail, data){
	var signFunc = null;
	if (contentType.indexOf("application/xml") === 0) {
		signFunc = this.makeXMLSign;
		data.attributes["actualSignatureType"] = this.OBJ_CADES_SIGNED_XML;
	} else if (contentType.indexOf("application/json") === 0
			|| contentType.indexOf("text/plain") === 0
      || contentType.indexOf("application/octet-stream") === 0
  ) {
		signFunc = this.makeCadesBesSign;
		data.attributes["actualSignatureType"] = this.OBJ_CADES_SIGNED_DATA;
	} else {
		onFail.call(this,"Unrecognized type received to be signed: '" + contentType + "'");
	}
	return signFunc;
}

CryptoPro.prototype.abort = function () {
  this.state = "ready";
};

CryptoPro.prototype.makeSign = function(params, onFail, onSuccess, onNeedCertSelect) {
  if (typeof cadesplugin === 'undefined') {
    return onFail(new Error('Plugin ES not connected'));
  }

	var me = this;
	if (me.state === "ready") {

    function mkSign(index, signFunc, data, cert) {
      var d = jQuery.Deferred();
      signFunc.call(me, data.parts[index], cert, function (sign, err) {
        if (err) {
          return d.reject(err);
        }
        d.resolve(sign);
      });
      return d;
    }

		this.state = "receiving";
		$.ajax({
			context: this,
		    type: "POST",
		    url: params.dataUrl,
		    data: {action: params.action},
		    //dataType: "text", // no conversion to XML, cryptopro accepts XML as text
		    beforeSend: function(xhr) {
			    xhr.setRequestHeader('x-requested-with', 'XMLHttpRequest');
		    }
		}).always(
			function(data, textStatus, jqXHR) {
				var success = (textStatus === "success") || (textStatus === "notmodified");
				if (success) {
					me.state = "signing";

					if (data.parts && data.parts.length > 0) {
						var doSign = function(certKey){
							try {
                me.getCertificate(certKey, function (cert, err) {
                  if (err || !cert) {
                    me.state = "ready";
                    return onFail.call(me, err || "Specified certificate was not found!");
                  }

                  var signFunc = null;
                  var deffereds = [];
                  for (var i = 0; i < data.parts.length; i++){
                    signFunc = me.getSignFunc(data.parts[i].mimeType, onFail, data);
                    deffereds.push(mkSign(i, signFunc, data, cert));
                  }

                  $.when.apply($, deffereds).then(function (signatures) {
                    me.sendSign(params, data, signatures, onFail, onSuccess);
                  }).fail(function (err) {
                    me.state = 'ready';
                    onFail.call(me, err);
                  });
                });
							} catch (err) {
                me.state = 'ready';
                onFail.call(me, err);
							}
						};

						if ("function" === typeof onNeedCertSelect){
							onNeedCertSelect.call(me,doSign);
						} else {
							me.getCerts(function (certs) {
                for (certKey in certs){
                  doSign(certKey);
                  return;
                }
                me.state = "ready";
                onFail.call(me, "There are no certificates to sign!");
              });
						}
					} else {
            me.state = "ready";
            onFail.call(me, "No signature data received!");
          }
				} else {
					me.state = "ready";
					onFail.call(me, textStatus);
				}
			});
	} else {
		onFail.call(me,"Unable to sign data. The module ES is busy with another task.");
	}
};

CryptoPro.prototype.sendSign = function(params, data, signatures, onFail, onSuccess) {
	this.state = "sending";
	var me = this;

	data.signatures = signatures;

	sd = {
		"action":params.action,
		"data":data.parts,
		"attributes":data.attributes,
		"signatures": (typeof signatures === 'string') ? [signatures] : signatures
	};

	$.ajax({
		context: this,
		type: "POST",
	    url: params.signUrl,
	    data: JSON.stringify(sd),
	    dataType:"json",
	    contentType: "application/json; charset=utf-8"/*,
	    beforeSend: function(xhr) {
		    xhr.setRequestHeader('x-requested-with', 'XMLHttpRequest');
	    }*/
	}).always(function(data, textStatus, jqXHR) {
		var success = (textStatus === "success");
		me.state = "ready";
		if (!success) {
			onFail.call(me, "Sending an ES failed, error code:" + textStatus + "'");
		} else {
	    	var dt = typeof data;
	    	if (dt !== "object") {
	    		onFail.call(me, "Sending an ES failed: wrong reply type received" + dt + "'");
	    	} else {
	    		if (data.message && data.type === "ERROR") {
	    			onFail.call(me, "Sending an ES failed: returned by server" + data.message + "'");
	    		} else if ("function" === typeof onSuccess){
	    			onSuccess.call(me);
	    		}
	    	}
		}
	});
};

//CryptoPro.prototype.notifyComplete = function

CryptoPro.prototype.getCertificate = function(thumbprint, cb) {
	// ??
	// var thumbprint = e.options[selectedCertID].value.split("
	// ").reverse().join(
	// "").replace(/\s/g, "").toUpperCase();
  if (typeof cadesplugin.CreateObject === 'function') {
    try {
      var oCerts = this.store.Certificates.Find(this.CAPICOM_CERTIFICATE_FIND_SHA1_HASH, thumbprint);
      if (oCerts.Count == 0) {
        return cb(null, new Error('Certificate not found!'));
      }
      var result = oCerts.Item(1);
      cb(result);
    } catch (e) {
      cb(null, e);
    }
  } else if (typeof cadesplugin.CreateObjectAsync === 'function') {
    var me = this;
    cadesplugin.async_spawn(function *(args) {
      var store;
      try {
        var certsObj = yield me.store.Certificates;
        var oCerts = yield certsObj.Find(me.CAPICOM_CERTIFICATE_FIND_SHA1_HASH, thumbprint);
        var Count = yield oCerts.Count;
        if (Count == 0) {
          return arg[0](null, new Error('Certificate not found!'));
        }
        var result = yield oCerts.Item(1);
        cb(result);
      } catch (e) {
        cb(null, e);
      }
    });
  } else {
   cb(null, new Error('Failed to get the certificate object!'));
  }
};

CryptoPro.prototype.makeCadesBesSign = function(dataToSign, certObject, cb) {
  if (typeof cadesplugin.CreateObject === 'function') {
    try {
      var oSigner = cadesplugin.CreateObject(this.OBJ_CADES_CP_SIGNER);
      oSigner.Certificate = certObject;
      oSigner.Options = this.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN;

      var oSignedData = cadesplugin.CreateObject(this.OBJ_CADES_SIGNED_DATA);
      oSignedData.ContentEncoding = 1;
      oSignedData.Content = dataToSign.content;

      var Signature = oSignedData.SignCades(oSigner, this.CADES_BES, dataToSign.attributes && dataToSign.attributes.detached);
      Signature = Signature.replace(/\r/g, "").replace(/\n/g, "");
      cb(Signature);
    } catch (e) {
      cb(null, e);
    }
  }  else if (typeof cadesplugin.CreateObjectAsync === 'function') {
    var me = this;
    cadesplugin.async_spawn(function *(args) {
      try {
        var oSigner = yield cadesplugin.CreateObjectAsync(me.OBJ_CADES_CP_SIGNER);
        var oSignedData = yield cadesplugin.CreateObjectAsync(me.OBJ_CADES_SIGNED_DATA);

        yield oSigner.propset_Certificate(certObject);
        yield oSigner.propset_Options(me.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN);

        yield oSignedData.propset_ContentEncoding(1);
        yield oSignedData.propset_Content(dataToSign.content);
        var Signature = yield oSignedData.SignCades(oSigner, me.CADES_BES, dataToSign.attributes && dataToSign.attributes.detached);
        Signature = Signature.replace(/\r/g, "").replace(/\n/g, "");
        cb(Signature);
      } catch (e) {
        cb(null, e);
      }
    });
  } else {
    cb(null, new Error('Signature failed!'));
  }
};

/**
 *
 * @param {{content: String}} dataToSign
 \* XML document to be signed. Document must
 \* be encoded UTF\-8\. If the document encoding is different from
 \* UTF-8, it should be encoded in BASE64
 * @param certObject
 \* Certificate
 \* @returns \(String\) Signed XML
 */
CryptoPro.prototype.makeXMLSign = function(dataToSign, certObject, cb) {
  if (typeof cadesplugin.CreateObject === 'function') {
    try {
      var oSigner = cadesplugin.CreateObject(this.OBJ_CADES_CP_SIGNER);
      oSigner.Certificate = certObject;
      oSigner.Options = this.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN;
      var oSignedXML = cadesplugin.CreateObject(this.OBJ_CADES_SIGNED_XML);
      oSignedXML.Content = dataToSign.content;
      oSignedXML.SignatureType = this.CADESCOM_XML_SIGNATURE_TYPE_ENVELOPING;
      oSignedXML.SignatureMethod = this.XML_DSIG_GOST_3410_URL;
      oSignedXML.DigestMethod = this.XML_DSIG_GOST_3411_URL;
      var sSignedMessage = oSignedXML.Sign(oSigner);
      cb(sSignedMessage.replace(/\r/g, "").replace(/\n/g, ""));
    } catch (e) {
      cb(null, e);
    }
  }  else if (typeof cadesplugin.CreateObjectAsync === 'function') {
    var me = this;
    cadesplugin.async_spawn(function *(args) {
      try {
        var oSigner = yield cadesplugin.CreateObjectAsync(me.OBJ_CADES_CP_SIGNER);
        var oSignedXML = yield cadesplugin.CreateObjectAsync(me.OBJ_CADES_SIGNED_XML);
        yield oSigner.propset_Certificate(certObject);
        yield oSigner.propset_Options(me.CAPICOM_CERTIFICATE_INCLUDE_WHOLE_CHAIN);

        yield oSignedXML.propset_Content(dataToSign.content);
        yield oSignedXML.propset_SignatureType(me.CADESCOM_XML_SIGNATURE_TYPE_ENVELOPING);
        yield oSignedXML.propset_SignatureMethod(me.XML_DSIG_GOST_3410_URL);
        yield oSignedXML.propset_DigestMethod(me.XML_DSIG_GOST_3411_URL);
        var sSignedMessage = yield oSignedXML.Sign(oSigner);
        cb(sSignedMessage.replace(/\r/g, "").replace(/\n/g, ""));
      } catch (e) {
        cb(null, e);
      }
    });
  } else {
    cb(null, new Error('Signature failed!'));
  }
};

CryptoPro.prototype.getCertFromSign = function(sign, cb) {
  if (typeof cadesplugin.CreateObject === 'function') {
    try {
      var result = [];
      var oSignedData = cadesplugin.CreateObject(this.OBJ_CADES_SIGNED_DATA);
      oSignedData.VerifyCades(sign, this.CADES_BES);
      var CertificatesObj = oSignedData.Certificates;
      var Count = CertificatesObj.Count;
      for (var i = 1; i <= Count; i++) {
        var cert = CertificatesObj.Item(i);
        var vtd = new Date(cert.ValidToDate);
        var vfd = new Date(cert.ValidFromDate);
        result.push(formCertInfo(cert));
      }
      cb(result);
    } catch (e) {
      cb(null, e);
    }
  } else if (typeof cadesplugin.CreateObjectAsync === 'function') {
    var me = this;
    cadesplugin.async_spawn(function *(args) {
      try {
        var result = [];
        var oSignedData = yield cadesplugin.CreateObjectAsync(me.OBJ_CADES_SIGNED_DATA);
        yield oSignedData.VerifyCades(sign, me.CADES_BES);
        var CertificatesObj = yield oSignedData.Certificates;
        var Count = yield CertificatesObj.Count;
        for (var i = 1; i <= Count; i++) {
          var cert = yield CertificatesObj.Item(i);
          var vtd = new Date(yield cert.ValidToDate);
          var vfd = new Date(yield cert.ValidFromDate);
          var key = yield cert.Thumbprint;
          var sn = yield cert.SubjectName;
          var isn = yield cert.IssuerName;
          var ser = yield cert.SerialNumber;
          result.push(formCertInfo(
            {
              SubjectName: sn,
              IssuerName: isn,
              SerialNumber: ser,
              ValidFromDate: vfd,
              ValidToDate: vtd
            }
          ));
        }
        cb(result);
      } catch (e) {
        cb(null, e);
      }
    });
  } else {
    cb(null, new Error('Failed to get a certificate!'));
  }
};

CryptoPro.prototype.verifySign = function(sign, cb) {
  if (typeof cadesplugin.CreateObject === 'function') {
    try {
      var result = [];
      var oSignedData = cadesplugin.CreateObject(this.OBJ_CADES_SIGNED_DATA);
      oSignedData.VerifyCades(sign, this.CADES_BES);
      cb(true);
    } catch (e) {
      cb(false);
    }
  } else if (typeof cadesplugin.CreateObjectAsync === 'function') {
    var me = this;
    cadesplugin.async_spawn(function *(args) {
      try {
        var result = [];
        var oSignedData = yield cadesplugin.CreateObjectAsync(me.OBJ_CADES_SIGNED_DATA);
        yield oSignedData.VerifyCades(sign, me.CADES_BES);
        cb(true);
      } catch (e) {
        cb(false);
      }
    });
  } else {
    cb(false);
  }
}