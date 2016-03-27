#微信公众号开发消息体签名及加密解密方案的GO语言实现

	e, err := NewEncrypter(token, encodingAesKey, appId)
	if err != nil {
		fmt.Println(err)
		return
	}

	//msgSignature, timestamp, nonce 微信服务器请求过来时在url中获取
	//msg为http POST请求中的body，即xml
	decryptedBytes, err = e.Decrypt(msgSignature, timestamp, nonce, msg)

	//msg为要回复的明文xml信息
	encryptedBytes, err := e.Encrypt(msg, timestamp, nonce)

###消息体加密

*微信正常消息为明文，格式如下：*

	msg = 
	<xml>
		<ToUserName><![CDATA[toUser]]></ToUserName>
		<FromUserName><![CDATA[fromUser]]></FromUserName> 
		<CreateTime>1348831860</CreateTime>
		<MsgType><![CDATA[text]]></MsgType>
		<Content><![CDATA[this is a test]]></Content>
		<MsgId>1234567890123456</MsgId>
	</xml>

*公众号选择了安全模式后，消息格式如下*， 调用`e.Decrypt(msgSignature, timestamp, nonce, new_msg)`解密

	new_msg=
	<xml> 
		<ToUserName><![CDATA[toUser]]</ToUserName>
	    <Encrypt><![CDATA[msg_encrypt]]</Encrypt>
	</xml>


微信服务器请求时在url上增加参数：msg_signature


|- 参数 -|- 说明 -|
|- Token -|- 公众平台上，开发者设置的Token -|
|- timestamp -|- URL上原有参数，时间戳 -|
|- nonce -|- URL上原有参数，随机数 -|
|- msg_encrypt -|- 前文描述密文消息体 -|


### 回复消息体的签名与加密

*明文格式：*

	msg=
	<xml>
		 <ToUserName><![CDATA[toUser]]></ToUserName>
		 <FromUserName><![CDATA[fromUser]]></FromUserName>
		 <CreateTime>12345678</CreateTime>
		 <MsgType><![CDATA[text]]></MsgType>
		 <Content><![CDATA[你好]]></Content>
	</xml>

调用`e.Encrypt(msg, timestamp, nonce)`加密

*加密后消息格式：*

	new_msg=
	<xml>
		<Encrypt><![CDATA[msg_encrypt]]></Encrypt>
		<MsgSignature><![CDATA[msg_signature]]></MsgSignature>
		<TimeStamp>timestamp</TimeStamp>
		<Nonce><![CDATA[nonce]]></Nonce>
	</xml> 