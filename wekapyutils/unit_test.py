import unittest
from pprint import pprint

#from wekassh2 import RemoteServer
from wekassh import RemoteServer
import fabric


class testWekassh(unittest.TestCase):
    """

    def test_pass_auth(self):
        connect_kwargs = {"password": "Administrator", "key_filename": [],
                          'disabled_algorithms': {'kex': ['rsa-sha2-512', 'rsa-sha2-256']}}
        #connect_kwargs = {"password": "WekaService", "key_filename": []}
        connection = fabric.Connection("172.29.3.1", user="Administrator", connect_kwargs=connect_kwargs)
        #connection = fabric.Connection("172.29.3.120", user="root", connect_kwargs=connect_kwargs)
        connection.open()
        #connection.run("date")
        print("complete")

    """
    def test_creates(self):
        server = RemoteServer("172.29.3.1")
        server.connect()
        result = server.run('date')
        pprint(result)
        # serverself.assertEqual(True, False)  # add assertion here


if __name__ == '__main__':
    unittest.main()
