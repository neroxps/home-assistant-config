import json
import requests
import os,re
import hashlib
import time
import base64
from urllib import parse

import voluptuous as vol
import homeassistant.helpers.config_validation as cv


import logging
_LOGGER = logging.getLogger(__name__)

CONF_USER = 'miid'
CONF_PASSWORD = 'password'

CONF_TO_NUM = 'miai_num'
ATTR_MESSAGE = 'message'
# {"message":".","miai_num":"0"}

DEFAULT_MIAI_NUM = '0'

DOMAIN = 'hello_miai'

SERVICE_SCHEMA = vol.Schema({
    vol.Required(ATTR_MESSAGE): cv.string,
    vol.Optional(CONF_TO_NUM): cv.string,
})



CONFIG_SCHEMA = vol.Schema({
    DOMAIN: vol.Schema({
        vol.Required(CONF_USER): cv.string,
        vol.Required(CONF_PASSWORD): cv.string,
    }),
}, extra=vol.ALLOW_EXTRA)

def setup(hass, config):
    conf = config.get(DOMAIN, {})
    miid = conf.get(CONF_USER)  
    password = conf.get(CONF_PASSWORD)  
    
    def send_message(call):

        to_num = call.data.get(CONF_TO_NUM, DEFAULT_MIAI_NUM)
        message = call.data.get(ATTR_MESSAGE) 
        client = xiaomi_tts(miid, password,login_info_dir=hass.config.config_dir+'/.xiaoai')       
        try:                        
            message = client.speech(message,to_num)
        except Exception as e:
            _LOGGER.error(e)

    hass.services.register(DOMAIN, 'send', send_message,
                           schema=SERVICE_SCHEMA)

    return True


class xiaomi_tts:

    def __init__(self,user=None,password=None,login_info_dir='../.xiaoai',can_input_capt=False):     
        self._can_input_capt=can_input_capt
        self.had_deviceID=True
        self._cookies={}
        self._request=requests.session() 
        self._login_info_dir= login_info_dir
        self._user=user
        self._password=password
        self._headers={'Host': 'account.xiaomi.com',
                    'Connection': 'keep-alive',
                    'Upgrade-Insecure-Requests': '1',
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36',
                    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
                    'Accept-Encoding': 'gzip, deflate, br',
                    'Accept-Language': 'zh-CN,zh;q=0.9'}
        if not os.path.exists(self._login_info_dir):
            os.makedirs(self._login_info_dir) 
        self._get_logon_info() 
        # self.had_deviceID = True


    def _get_sign(self): 
        url = 'https://account.xiaomi.com/pass/serviceLogin?sid=micoapi'
        pattern = re.compile(r'_sign":"(.*?)",')
        try:            
            r = self._request.get(url,headers=self._headers,timeout=3)
            self._cookies['JSESSIONID']=self._request.cookies.get_dict()['JSESSIONID']
            self._cookies['deviceId']=self._request.cookies.get_dict()['deviceId']
            self._cookies['pass_trace']=self._request.cookies.get_dict()['pass_trace']
            self._cookies['pass_ua']=self._request.cookies.get_dict()['pass_ua']
            self._cookies['uLocale']=self._request.cookies.get_dict()['uLocale']

            return pattern.findall(r.text)[0]
        except BaseException as e:
            _LOGGER.error('_get_sign',e) 
            return False 

    def _serviceLoginAuth2(self,captCode=None):
        url='https://account.xiaomi.com/pass/serviceLoginAuth2'
        if captCode==None:
            self._headers['Content-Type']='application/x-www-form-urlencoded'
            self._headers['Accept']='*/*'
            self._headers['Origin']='https://account.xiaomi.com'
            self._headers['Referer']='https://account.xiaomi.com/pass/serviceLogin?sid=micoapi'
            self._sign=self._get_sign()  #获取sign  
            if self._sign == False:  #判断是否获取成功
                _LOGGER.error('获取_sign出错！',) 
                return              
            self._headers['Cookie']='pass_ua={}; deviceId={}; pass_trace={}; uLocale={}; JSESSIONID={}'.format(self._cookies['pass_ua'],self._cookies['deviceId'],self._cookies['pass_trace'],self._cookies['uLocale'],self._cookies['JSESSIONID'])        
            auth_post_data={'_json':'true',
                        '_sign':self._sign,
                        'callback':'https://api.mina.mi.com/sts',
                        'hash':hashlib.md5(self._password.encode('utf-8')).hexdigest().upper(),
                        'qs':'%3Fsid%3Dmicoapi',
                        'serviceParam':'{"checkSafePhone":false}',
                        'sid':'micoapi',
                        'user':self._user}        
        else:
            url='https://account.xiaomi.com/pass/serviceLoginAuth2?_dc={}'.format(int(round(time.time() * 1000)))
            auth_post_data['captCode']=captCode
    
        try:
            if captCode!=None:
                self._headers['Cookie']=self._headers['Cookie']+'; ick={}'.format(self._cookies['ick'])
            r= self._request.post(url,headers=self._headers,data=auth_post_data,timeout=3,cookies=self._cookies)
            # _LOGGER.error(self._request.cookies.get_dict()['pwdToken'])
            if captCode==None:
                self._cookies['pwdToken']=self._request.cookies.get_dict()['pwdToken']
            _serviceLoginAuth2_json=json.loads(r.text[11:])
            # _LOGGER.error(_serviceLoginAuth2_json)
            return _serviceLoginAuth2_json
        except BaseException as e:
            _LOGGER.error('_serviceLoginAuth2',e)  


    def _finish_login(self,_serviceLoginAuth2_json):
        nonce=_serviceLoginAuth2_json['nonce']
        ssecurity=_serviceLoginAuth2_json['ssecurity']
        serviceToken = "nonce={}&{}".format(nonce,ssecurity)
        serviceToken_sha1=hashlib.sha1(serviceToken.encode('utf-8')).digest()
        base64_serviceToken = base64.b64encode(serviceToken_sha1)
        login_miai_url=_serviceLoginAuth2_json['location']+"&clientSign="+parse.quote(base64_serviceToken.decode())
        miai_session=self._login_miai(login_miai_url)
        if miai_session!=False:                    
            miai_session_userId=miai_session['userId']
            miai_session_serviceToken=miai_session['serviceToken']
            return self._get_deviceId(miai_session_userId,miai_session_serviceToken)     
        else:
            return False  


    def _serviceToken(self):
        _serviceLoginAuth2_json=self._serviceLoginAuth2()
        if _serviceLoginAuth2_json['code']==0:
            return self._finish_login(_serviceLoginAuth2_json)                 
        elif _serviceLoginAuth2_json['code']==87001:
            if self._can_input_capt==True:                
                self._headers['Cookie']=self._headers['Cookie']+'; pwdToken={}'.format(self._cookies['pwdToken'])
                try:                
                    r= self._request.get('https://account.xiaomi.com/pass/getCode?icodeType=login&{}'.format(int(round(time.time() * 1000))),headers=self._headers,timeout=3,cookies=self._cookies)         
                    self._cookies['ick']=self._request.cookies.get_dict()['ick'] 
                    with open(self._login_info_dir+'/capt.jpg','wb') as f:  
                        f.write(r.content)  
                        f.close()  
                except BaseException as e:
                    _LOGGER.error('get_capt_code_image',e)    
                capt_code = input('请输入验证码:')
                _serviceLoginAuth2_json=self._serviceLoginAuth2(capt_code)
                if _serviceLoginAuth2_json['code']==0:
                    return self._finish_login(_serviceLoginAuth2_json)
            else:
                _LOGGER.error("请手动运行hello_miai.py文件，并在/.xiaoai/中找到capt.jpg,查看并且输入验证码。")
        elif _serviceLoginAuth2_json['code']==70016:
            _LOGGER.error("账号或者密码错误")
            return False
        else:
            _LOGGER.error(_serviceLoginAuth2_json)
            return False


    def _login_miai(self,url):
        miai_header={'User-Agent': 'MISoundBox/1.4.0,iosPassportSDK/iOS-3.2.7 iOS/11.2.5','Accept-Language': 'zh-cn','Connection': 'keep-alive'}
        try:            
            r = self._request.get(url,headers=miai_header,timeout=3)
            return self._request.cookies.get_dict()
            # return pattern.findall(r.text)[0]
        except BaseException as e :
            _LOGGER.error('_login_miai',e)
            return False  

    def _get_deviceId(self,userId,serviceToken):
        url='https://api.mina.mi.com/admin/v2/device_list?master=1&requestId=CdPhDBJMUwAhgxiUvOsKt0kwXThAvY'
        get_deviceId_header={'Cookie': 'userId={};serviceToken={}'.format(userId,serviceToken)}
        try:            
            r = self._request.get(url,headers=get_deviceId_header,timeout=3)            
            model={"Cookie": "userId={};serviceToken={}".format(userId,serviceToken),"deviceId":json.loads(r.text)['data']}
            with open(self._login_info_dir+'/config.json','w',encoding='utf-8') as json_file:
                json.dump(model,json_file,ensure_ascii=False)
                json_file.close() 
            # self.tts_cookie="userId={};serviceToken={}".format(userId,serviceToken)
            # # self.deviceId=json.loads(r.text)['data']
            # self.deviceId=json.loads(r.text)['data'][0]['deviceID']                                  
        except BaseException as e :
            _LOGGER.error('_get_deviceId',e)
            return False        


    def _text_to_speech(self,text,count=0):
        try:   
            url = "https://api.mina.mi.com/remote/ubus?deviceId={}&message=%7B%22text%22%3A%22{}%22%7D&method=text_to_speech&path=mibrain&requestId={}".format(self.deviceId,parse.quote(text),'rb1gB2aATpRd7jfOpaT3pxp85ndZ7t')         
            r = self._request.post(url,headers={'Cookie':self.tts_cookie},timeout=3)
            _LOGGER.info(json.loads(r.text))
            if json.loads(r.text)['message'] == 'Success':
                return True
            else:
                return False
        except AttributeError as e:
            _LOGGER.error('_text_to_speech_AttributeError',e)
        except BaseException as e :
            _LOGGER.error('_text_to_speech',e)     
            if count>=2:
                return False
            self._text_to_speech(text,count=count+1)   

    def _get_logon_info(self,num=0):
        try:            
            with open(self._login_info_dir+'/config.json','r',encoding='utf-8') as json_file:
                model=json.load(json_file) 
                json_file.close()
            self.tts_cookie=model['Cookie']
            self.deviceId=model['deviceId'][num]['deviceID']
        except IOError as e:            
            self._serviceToken()  
        except IndexError as e:
            _LOGGER.error('你没有那个音箱！') 
            self.had_deviceID=False  

    def speech(self,text,num='0'):
        self._get_logon_info(int(num))
        if self.had_deviceID!=False:
            if self._text_to_speech(text,count=2) == False:
                if self._serviceToken() !=False:
                    self._get_logon_info(int(num))
                    self._text_to_speech(text)


if __name__ =='__main__':   
    miid=input('请输入米家账号:')    
    password=input('请输入密码:')
    num=input('请输入音箱编号(从0开始):')
    xiaomi_tts(miid,password,login_info_dir='../.xiaoai',can_input_capt=True).speech("Token已生成",int(num))
