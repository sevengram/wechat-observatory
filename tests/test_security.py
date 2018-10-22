import random

import pytest

from observatory.security import Prpcrypt

encoding_key = 'abcdefghijklmnopqrstuvwxyz123456789ABCDEFGH'
appid = 'abcdefghi123456789'


def test_encrypt():
  random.seed(12345678)
  crypter = Prpcrypt(key=encoding_key)
  ciphertext = crypter.encrypt('hello', appid)
  assert ciphertext == 'CXziYSPS/WXussMF5qH/oLIGYpG62U9vbFZUgzDae1Gkf2Bvt' + \
         '6DGt8a9C141hc2hLUrCj48rP68LVJbraj3oLA=='


def test_decrypt():
  crypter = Prpcrypt(key=encoding_key)
  ciphertext = 'UswbiAP/6RLi7EVHdWbT+KrujYmdoEYuMoZ4wHggjPXTd1lKAi99ScwaM' + \
               'g0Tjl9ketAtANfsrwAhcGwBWJRLdQ=='
  assert crypter.decrypt(ciphertext, appid) == 'hello'


def test_decrypt_unmatched_appid():
  crypter = Prpcrypt(key=encoding_key)
  ciphertext = 'UswbiAP/6RLi7EVHdWbT+KrujYmdoEYuMoZ4wHggjPXTd1lKAi99ScwaM' + \
               'g0Tjl9ketAtANfsrwAhcGwBWJRLdQ=='
  with pytest.raises(ValueError) as excinfo:
    crypter.decrypt(ciphertext, '1234567')
  assert str(excinfo.value) == 'Unmatched AppID'


def test_encrypt_decrypt():
  crypter = Prpcrypt(key=encoding_key)
  plain_text = 'hello_WORLD 12345!<>;()'
  ciphertext = crypter.encrypt(plain_text, appid)
  assert crypter.decrypt(ciphertext, appid) == plain_text


def test_encrypt_decrypt_unicode():
  crypter = Prpcrypt(key=encoding_key)
  plain_text = '\u4e2d\u56fd\u5317\u4eac'
  ciphertext = crypter.encrypt(plain_text, appid)
  assert crypter.decrypt(ciphertext, appid) == plain_text
