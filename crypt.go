package wechat

type encrypter struct {
	prpcrypter     *Prpcrypt
	token          string
	encodingAesKey string
	appId          string
}

func NewEncrypter(token, encodingAesKey, appId string) (e *encrypter, err error) {
	if len(encodingAesKey) != 43 {
		err = IllegalAesKey
		return
	}

	p, err := newPrpcrypt(encodingAesKey)
	if err != nil {
		return
	}

	e = &encrypter{
		prpcrypter:     p,
		token:          token,
		appId:          appId,
		encodingAesKey: encodingAesKey,
	}
	return
}

func (e *encrypter) Encrypt(replyMsg []byte, timestamp, nonce string) (b []byte, err error) {
	encrypt, err := e.prpcrypter.Encrypt(e.appId, replyMsg)
	if err != nil {
		return
	}

	signature := Sha1(e.token, timestamp, nonce, encrypt)

	b, err = GenerateResponseXML(encrypt, signature, timestamp, nonce)
	return
}

func (e *encrypter) Decrypt(msgSignature, timestamp, nonce string, data []byte) (b []byte, err error) {
	reqXML, err := ParseRequestXML(data)
	if err != nil {
		return
	}

	signature := Sha1(e.token, timestamp, nonce, reqXML.Encrypt)
	if signature != msgSignature {
		err = ValidateSignatureError
		return
	}
	b, err = e.prpcrypter.Decrypt(e.appId, reqXML.Encrypt)
	return
}
