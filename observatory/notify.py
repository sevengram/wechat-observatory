import hashlib
import random
import time
import urllib.parse
from collections import defaultdict

import requests
import xmltodict
from flask import Blueprint, current_app, request, abort

from observatory.security import Prpcrypt

bp = Blueprint('notify', __name__, url_prefix='/notify')

msg_type_dict = defaultdict(lambda: ['default'], {
  'image': ['astrometry'],
  'location': ['weather_location'],
  'text': ['weather_text', 'default'],
  'event': ['welcome']
})


def process_weather_text(request_data):
  query = request_data.get('Content', '')
  if len(query) < 2 or (query[0].isdigit() and len(query) == 2):
    return None
  weather_resp = requests.get('http://127.0.0.1/weather',
                              params={'query': query}).json()
  if weather_resp['formatted_address']:
    return build_news_response(
        server_id=request_data['ToUserName'],
        user_id=request_data['FromUserName'],
        title=weather_resp['formatted_address'],
        description='数据来自晴天钟(www.7timer.info)',
        url=weather_resp['7timer_url'])
  return None


def process_weather_location(request_data):
  img_url = 'http://www.7timer.info/bin/astro.php?' + urllib.parse.urlencode(
      {'lon': request_data['Location_Y'],
       'lat': request_data['Location_X'],
       'lang': 'zh-CN',
       'time': int(time.time())
       })
  return build_news_response(
      server_id=request_data['ToUserName'],
      user_id=request_data['FromUserName'],
      title=request_data['Label'],
      description='数据来自晴天钟(www.7timer.info)',
      url=img_url)


def process_echo(request_data):
  return build_text_response(
      server_id=request_data['ToUserName'],
      user_id=request_data['FromUserName'],
      content=request_data['Content'])


def process_default(request_data):
  return build_text_response(
      server_id=request_data['ToUserName'],
      user_id=request_data['FromUserName'],
      content="感谢留言.\n"
              "查询晴天钟天气: 请输入地名或者点击加号发送位置\n"
              "这其实是一个分析天气变化的公众号.")


def process_welcome(request_data):
  return build_text_response(
      server_id=request_data['ToUserName'],
      user_id=request_data['FromUserName'],
      content="欢迎来到邻家天文馆！\n"
              "查询晴天钟天气: 请输入地名或者点击加号发送位置\n"
              "这其实是一个分析天气变化的公众号.\n"
              "- - - - - - - -\n"
              "大道之行也, 天下为公. 选贤与能, 讲信修睦, 故人不独亲其亲, 不独子其子, "
              "使老有所终, 壮有所用, 幼有所长, 鳏寡孤独废疾者皆有所养. 《礼记》")


process_dict = {
  'weather_location': process_weather_location,
  'weather_text': process_weather_text,
  'default': process_default,
  'welcome': process_welcome,
  'test': process_echo
}


@bp.route('', methods=['GET', 'POST'])
def notify():
  config = current_app.config
  sign_key = config['SIGN_KEY']
  if not current_app.config['DEBUG'] and not is_valid_args(
      request.args, sign_key):
    abort(400)
  if request.method == 'GET':
    return request.args.get('echostr', '')
  else:  # request.method == 'POST':
    appid = config['APP_ID']
    crypter = Prpcrypt(config['ENCODING_KEY'])
    request_data = xml2dict(request.data)
    request_data = xml2dict(crypter.decrypt(request_data['Encrypt'], appid))
    for p in msg_type_dict[request_data['MsgType']]:
      if p in process_dict:
        response = process_dict[p](request_data)
        if response:
          current_app.logger.info(response)
          return dict2xml(encrypt_and_sign(response, appid, sign_key, crypter))
    abort(400)


def is_valid_args(args, sign_key):
  if any(k not in args for k in ('timestamp', 'nonce', 'signature')):
    return False
  return build_signature({k: args[k] for k in ('timestamp', 'nonce')},
                         sign_key) == args['signature']


def build_signature(response_data, sign_key):
  p = [str(field) for field in response_data.values()] + [sign_key]
  p.sort()
  return hashlib.sha1(''.join(p).encode('utf8')).hexdigest()


def build_text_response(server_id, user_id, content):
  return {
    'FromUserName': server_id,
    'ToUserName': user_id,
    'MsgType': 'text',
    'Content': content,
    'CreateTime': int(time.time())
  }


def build_news_response(server_id, user_id, title, description, url):
  return {
    'FromUserName': server_id,
    'ToUserName': user_id,
    'CreateTime': int(time.time()),
    'MsgType': 'news',
    'ArticleCount': 1,
    'Articles': [
      {
        'item': {
          'Title': title,
          'Description': description,
          'PicUrl': url,
          'Url': url
        }
      }
    ]
  }


def encrypt_and_sign(response_data, appid, sign_key, crypter):
  result = {'Encrypt': crypter.encrypt(dict2xml(response_data), appid),
            'Nonce': str(random.randint(1, 1e10)),
            'TimeStamp': int(time.time())}
  result['MsgSignature'] = build_signature(result, sign_key)
  return result


def xml2dict(xml):
  return xmltodict.parse(xml)['xml']


def dict2xml(dic):
  return xmltodict.unparse({'xml': dic}, full_document=False)
