def test_notify_echo(client):
  echostr = '3300416197047605133'
  response = client.get('/notify', query_string={
    'signature': '47250333e90a8153a6bfdace5b3933ed9cf51cb9',
    'echostr': echostr,
    'timestamp': '1539577740',
    'nonce': '230265772'
  })
  assert response.status_code == 200
  assert response.data == b'3300416197047605133'


def test_notify_invalid_signature(client):
  echostr = '3300416197047605133'
  response = client.get('/notify', query_string={
    'signature': 'invalid_signature',
    'echostr': echostr,
    'timestamp': '1539577740',
    'nonce': '230265772'
  })
  assert response.status_code == 400
