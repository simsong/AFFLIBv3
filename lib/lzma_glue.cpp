#include "affconfig.h"
#include "afflib.h"
#include "afflib_i.h"

/*
 * Distributed under the Berkeley 4-part license
 * Simson L. Garfinkel, March 12, 2012
 */


#include "../../../Common/MyWindows.h"
#include "../../../Common/MyInitGuid.h"
#include "../../Common/FileStreams.h"
#include "../../Common/StreamUtils.h"
#include "../LZMA/LZMADecoder.h"
#include "../LZMA/LZMAEncoder.h"
#include "LzmaBench.h"

#include "LzmaRam.h"
extern "C" {
#include "LzmaRamDecode.h"
}

class CInMemoryStream: public ISequentialInStream, public CMyUnknownImp {
public:
    const unsigned char *buf;
    size_t  buflen;
    size_t  ptr;
    virtual ~CInMemoryStream(){}
    CInMemoryStream(const unsigned char *buf_,size_t len){
	buf    = buf_;
	buflen = len;
	ptr    = 0;
    }

    MY_UNKNOWN_IMP1(IInStream)
	STDMETHOD(Read)(void *data, UInt32 size, UInt32 *processedSize){
	if(ptr+size > buflen) size = buflen - ptr; // max that can be read
	memcpy(data,buf+ptr,size);
	ptr += size;
	if(processedSize) *processedSize = size;
	return S_OK;
    }
};


class COutMemoryStream: public ISequentialOutStream, public CMyUnknownImp {
public:
    unsigned char *buf;
    size_t  buflen;
    size_t  ptr;
    size_t  *notify;
    virtual ~COutMemoryStream(){}
    COutMemoryStream(unsigned char *buf_,size_t len,size_t *notify_){
	buf    = buf_;
	buflen = len;
	ptr    = 0;
	notify = notify_;
    }

    MY_UNKNOWN_IMP1(IOutStream) STDMETHOD(Write)(const void *data, UInt32 size,
						 UInt32 *processedSize){
	if(ptr+size > buflen) return E_FAIL;
	memcpy(buf+ptr,data,size);
	ptr += size;
	if(processedSize) *processedSize = size;
	if(notify)        *notify = ptr;
	return S_OK;
    }
};

/*
 * Attempt to compress. Return -1 if fail.
 * (Fails if compression results in expansion.
 */

int lzma_compress(unsigned char *dest,size_t *destLen,const unsigned char *data,size_t datalen,int level)
{
    PROPID propIDs[] = {
	NCoderPropID::kDictionarySize,
	NCoderPropID::kPosStateBits,
	NCoderPropID::kLitContextBits,
	NCoderPropID::kLitPosBits,
	NCoderPropID::kAlgorithm,
	NCoderPropID::kNumFastBytes,
	NCoderPropID::kMatchFinder,
	NCoderPropID::kEndMarker
    };
    const int nprops = sizeof(propIDs) / sizeof(propIDs[0]);
    PROPVARIANT p[nprops];

    p[0].vt = VT_UI4; p[0].ulVal = UInt32(1 << 24);
    p[1].vt = VT_UI4; p[1].ulVal = UInt32(2); // posBits
    p[2].vt = VT_UI4; p[2].ulVal = UInt32(3); // literal context bits
    p[3].vt = VT_UI4; p[3].ulVal = UInt32(0); // literal pos bits
    p[4].vt = VT_UI4; p[4].ulVal = UInt32(2); // compression mode
    p[5].vt = VT_UI4; p[5].ulVal = UInt32(128);	// fast_bytes

    // old code generates warnings now
    //p[6].vt = VT_BSTR; p[6].bstrVal = L"bt4"; // it's okay; we won't change it

    // new code
    const void *temp = L"bt4";
    p[6].vt = VT_BSTR; p[6].bstrVal = (OLECHAR *)temp; // it's okay; we won't change it

    p[7].vt = VT_BOOL; p[7].boolVal = VARIANT_FALSE;

    NCompress::NLZMA::CEncoder *encoder = new NCompress::NLZMA::CEncoder;

    if (encoder->SetCoderProperties(propIDs, p, nprops) != S_OK){
      return -1; /* Couldn't set encoder properties */
    }

    /* Open and configure the output stream */
    UInt64 fileSize = datalen;
    COutMemoryStream *outStream = new COutMemoryStream(dest,*destLen,destLen);
    outStream->AddRef();

    encoder->WriteCoderProperties(outStream);

    for (int i = 0; i < 8; i++) {
	Byte b = Byte(fileSize >> (8 * i));
	if (outStream->Write(&b, sizeof(b), 0) != S_OK){
	    outStream->Release();
	    return -1; /* Write error while encoding */
	}
    }

    CInMemoryStream *inStream = new CInMemoryStream(data,datalen);
    inStream->AddRef();
    HRESULT result = encoder->Code(inStream, outStream, 0, 0, 0);
    inStream->Release();
    outStream->Release();
    delete(encoder);

    return result;
}


int lzma_uncompress(unsigned char *buf,size_t *buflen, const unsigned char *cbuf,size_t cbuf_size)
{
    CInMemoryStream *inStream = new CInMemoryStream(cbuf,cbuf_size);
    inStream->AddRef();

    const UInt32 kPropertiesSize = 5;
    Byte properties[kPropertiesSize];
    UInt32 processedSize;
    UInt64 fileSize = 0;
    NCompress::NLZMA::CDecoder decoderSpec;

    if (inStream->Read(properties, kPropertiesSize, &processedSize) != S_OK){
	inStream->Release();
	return -1;
    }
    if (processedSize != kPropertiesSize) return -1;
    if (decoderSpec.SetDecoderProperties2(properties, kPropertiesSize) != S_OK){
	inStream->Release();
	return -1;
    }

    for (int i = 0; i < 8; i++) {
	Byte b;
	if (inStream->Read(&b, sizeof(b), &processedSize) != S_OK) return -1;
	if (processedSize != 1){
	    inStream->Release();
	    return -1;
	}
	fileSize |= ((UInt64)b) << (8 * i);
    }

    COutMemoryStream *outStream = new COutMemoryStream(buf,*buflen,buflen);
    outStream->AddRef();
    int r = decoderSpec.Code(inStream, outStream, 0, &fileSize, 0);
    inStream->Release();
    outStream->Release();
    return r;
}

