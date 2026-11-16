from support import Fixture, run, verify_signature
import base64
import gzip
import json
from urllib.parse import parse_qs, unquote, urlsplit

class Handler(Fixture):

    def route(self, body):
        service = verify_signature(self, body)
        target = self.headers.get('X-Amz-Target', '').split('.')[-1]
        self.server.calls[target] = self.server.calls.get(target, 0) + 1
        assert service == 'kms'
        data = json.loads(body)
        if target == 'ListKeys':
            if 'Marker' not in data:
                result = {'Keys': [{'KeyArn': 'key1'}], 'Truncated': True, 'NextMarker': 'next+/?'}
            else:
                assert data['Marker'] == 'next+/?'
                result = {'Keys': [{'KeyArn': 'key2'}], 'Truncated': False}
        elif target in ('CreateKey', 'DescribeKey'):
            result = {'KeyMetadata': {'Arn': 'arn', 'Enabled': True}}
        elif target == 'Encrypt':
            assert base64.b64decode(data['Plaintext']) == b'\x00\xff\x80'
            result = {'CiphertextBlob': 'AP+A'}
        elif target == 'Decrypt':
            assert base64.b64decode(data['CiphertextBlob']) == b'\x00\xff\x80'
            result = {'Plaintext': 'AP+A'}
        elif target == 'GenerateDataKey':
            assert data['NumberOfBytes'] == 32
            result = {'Plaintext': 'AP+A', 'CiphertextBlob': 'AP+A'}
        elif target == 'GenerateRandom':
            assert data['NumberOfBytes'] == 3
            result = {'Plaintext': 'AP+A'}
        elif target == 'ScheduleKeyDeletion':
            assert data['PendingWindowInDays'] == 7
            result = {'DeletionDate': 1900000000}
        else:
            assert target in ('EnableKey', 'DisableKey', 'CancelKeyDeletion')
            result = {}
        if target not in ('ListKeys', 'CreateKey', 'Decrypt', 'GenerateRandom'):
            assert data['KeyId'] == 'arn'
        self.reply(200, result)
if __name__ == '__main__':
    run(Handler)
