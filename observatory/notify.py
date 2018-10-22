import hashlib
import random
import time

import xmltodict
from flask import Blueprint, current_app, request, abort

from observatory.security import Prpcrypt

bp = Blueprint('notify', __name__, url_prefix='/notify')


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
    if request_data['MsgType'] == 'text':
      response = build_echo_response(request_data)
      current_app.logger.info(response)
      return dict2xml(encrypt_and_sign(response, appid, sign_key, crypter))
    else:
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


def build_echo_response(request_data):
  server_id = request_data['ToUserName']
  user_id = request_data['FromUserName']
  content = request_data['Content']
  return build_text_response(server_id, user_id, content)


def build_text_response(server_id, user_id, content):
  return {
    'FromUserName': server_id,
    'ToUserName': user_id,
    'MsgType': 'text',
    'Content': content,
    'CreateTime': int(time.time())
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
