package wechat

import (
	"encoding/xml"
	"fmt"
)

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

func main() {
	encodingAesKey := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG"
	token := "pamtest"
	timestamp := "1409304348"
	nonce := "xxxxxx"
	appId := "wxb11529c136998cb6"
	text := "<xml><ToUserName><![CDATA[oia2Tj我是中文jewbmiOUlr6X-1crbLOvLw]]></ToUserName><FromUserName><![CDATA[gh_7f083739789a]]></FromUserName><CreateTime>1407743423</CreateTime><MsgType><![CDATA[video]]></MsgType><Video><MediaId><![CDATA[eYJ1MbwPRJtOvIEabaxHs7TX2D-HV71s79GUxqdUkjm6Gs2Ed1KF3ulAOA9H1xG0]]></MediaId><Title><![CDATA[testCallBackReplyVideo]]></Title><Description><![CDATA[testCallBackReplyVideo]]></Description></Video></xml>"

	e, err := NewEncrypter(token, encodingAesKey, appId)
	if err != nil {
		fmt.Println(err)
		return
	}

	b, err := e.Encrypt([]byte(text), timestamp, nonce)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(string(b))
	var v EncryptedResponseXML
	err = xml.Unmarshal(b, &v)
	if err != nil {
		fmt.Println("unmarshal responseXML err : ", err)
		return
	}

	msgSignature := v.MsgSignature
	encrypt := v.Encrypt

	formatXML := fmt.Sprintf(
		"<xml><ToUserName><![CDATA[toUser]]></ToUserName><Encrypt><![CDATA[%s]]></Encrypt></xml>",
		encrypt)
	b, err = e.Decrypt(msgSignature, timestamp, nonce, []byte(formatXML))
	if err != nil {
		fmt.Println("decrypt error: ", err)
		return
	}

	fmt.Println("decrypt result", string(b))

}
