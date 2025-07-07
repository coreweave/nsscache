# Copyright 2025 Google Inc.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
"""Unit tests for SCIM data source for nsscache."""

__author__ = "tbecker@coreweave.com (Tyler Becker)"

import json
import os
import unittest
import pycurl
from unittest import mock

from nss_cache import error
from nss_cache.maps import group
from nss_cache.maps import passwd
from nss_cache.maps import sshkey

from nss_cache.sources import scimsource
from nss_cache.util import curl


class TestScimSource(unittest.TestCase):
    def setUp(self):
        """Initialize a basic config dict."""
        super(TestScimSource, self).setUp()
        self.config = {
            "base_url": "https://api.example.com/scim",
            "auth_token": "test_token",
            "users_endpoint": "Users",
            "groups_endpoint": "Groups",
            "timeout": 30,
            "verify_ssl": True,
            "retry_delay": 3,
            "retry_max": 2,
            "default_shell": "/bin/zsh",
        }

    def testDefaultConfiguration(self):
        """Test that default configuration values are set correctly."""
        config = {
            "base_url": "https://api.example.com/scim",
            "auth_token": "test_token"
        }
        source = scimsource.ScimSource(config)
        
        self.assertEqual(source.conf["users_endpoint"], scimsource.ScimSource.USERS_ENDPOINT)
        self.assertEqual(source.conf["groups_endpoint"], scimsource.ScimSource.GROUPS_ENDPOINT)
        self.assertEqual(source.conf["timeout"], scimsource.ScimSource.TIMEOUT)
        self.assertEqual(source.conf["verify_ssl"], scimsource.ScimSource.VERIFY_SSL)
        self.assertEqual(source.conf["retry_delay"], scimsource.ScimSource.RETRY_DELAY)
        self.assertEqual(source.conf["retry_max"], scimsource.ScimSource.RETRY_MAX)
        self.assertEqual(source.conf["default_shell"], scimsource.ScimSource.DEFAULT_SHELL)

    def testOverrideDefaultConfiguration(self):
        """Test that configuration values can be overridden."""
        source = scimsource.ScimSource(self.config)
        
        self.assertEqual(source.conf["base_url"], "https://api.example.com/scim")
        self.assertEqual(source.conf["auth_token"], "test_token")
        self.assertEqual(source.conf["users_endpoint"], "Users")
        self.assertEqual(source.conf["groups_endpoint"], "Groups")
        self.assertEqual(source.conf["timeout"], 30)
        self.assertEqual(source.conf["verify_ssl"], True)
        self.assertEqual(source.conf["retry_delay"], 3)
        self.assertEqual(source.conf["retry_max"], 2)
        self.assertEqual(source.conf["default_shell"], "/bin/zsh")

    def testMissingBaseUrlRaisesError(self):
        """Test that missing base_url raises ConfigurationError."""
        config = {"auth_token": "test_token"}
        
        with self.assertRaises(error.ConfigurationError) as cm:
            scimsource.ScimSource(config)
        
        self.assertIn("base_url and auth_token are required", str(cm.exception))

    def testMissingAuthTokenRaisesError(self):
        """Test that missing auth_token raises ConfigurationError."""
        config = {"base_url": "https://api.example.com/scim"}
        
        with self.assertRaises(error.ConfigurationError) as cm:
            scimsource.ScimSource(config)
        
        self.assertIn("base_url and auth_token are required", str(cm.exception))

    @mock.patch.dict(os.environ, {'NSSCACHE_SCIM_AUTH_TOKEN': 'env_token'})
    def testAuthTokenFromEnvironment(self):
        """Test that auth_token can be loaded from environment variable."""
        config = {"base_url": "https://api.example.com/scim"}
        source = scimsource.ScimSource(config)
        
        self.assertEqual(source.conf["auth_token"], "env_token")

    def testVerifySslDisabled(self):
        """Test that SSL verification can be disabled."""
        config = {
            "base_url": "https://api.example.com/scim",
            "auth_token": "test_token",
            "verify_ssl": False
        }
        
        with mock.patch('pycurl.Curl') as mock_curl:
            mock_conn = mock.Mock()
            mock_curl.return_value = mock_conn
            
            source = scimsource.ScimSource(config)
            
            mock_conn.setopt.assert_any_call(pycurl.SSL_VERIFYPEER, 0)
            mock_conn.setopt.assert_any_call(pycurl.SSL_VERIFYHOST, 0)


class TestScimUpdateGetter(unittest.TestCase):
    def setUp(self):
        super().setUp()
        curl_patcher = mock.patch.object(pycurl, "Curl")
        self.addCleanup(curl_patcher.stop)
        self.curl_mock = curl_patcher.start()

    def testGetUpdatesWithPagination(self):
        """Test that pagination works correctly."""
        mock_conn = mock.Mock()
        mock_conn.getinfo.return_value = 200
        self.curl_mock.return_value = mock_conn
        
        config = {
            "base_url": "https://api.example.com/scim",
            "auth_token": "test_token",
            "items_per_page": 50
        }
        source = scimsource.ScimSource(config)
        
        getter = scimsource.UpdateGetter()
        getter.source = source
        getter.GetParser = mock.Mock()
        getter.CreateMap = mock.Mock(return_value=mock.Mock())
        
        # Mock super().GetUpdates to return mock maps
        with mock.patch.object(scimsource.HttpUpdateGetter, 'GetUpdates') as mock_super:
            # First page returns 50 items (full page), second page returns 25 items (partial page)
            mock_first_map = mock.Mock()
            mock_first_map.Add = mock.Mock(return_value=True)
            mock_first_map.__len__ = mock.Mock(return_value=50)
            
            mock_second_map = mock.Mock()
            mock_second_map.__iter__ = mock.Mock(return_value=iter([mock.Mock()]))
            mock_second_map.__len__ = mock.Mock(return_value=25)
            
            mock_super.side_effect = [mock_first_map, mock_second_map]
            
            result = getter.GetUpdates(source, "https://api.example.com/scim/Users", None)
            
            # Should call super().GetUpdates twice (first page + second page)
            self.assertEqual(mock_super.call_count, 2)
            
            # Verify the URLs include pagination parameters
            call_args = mock_super.call_args_list
            self.assertIn("startIndex=1", call_args[0][0][1])
            self.assertIn("count=50", call_args[0][0][1])
            self.assertIn("startIndex=51", call_args[1][0][1])
            self.assertIn("count=50", call_args[1][0][1])


class TestScimPasswdUpdateGetter(unittest.TestCase):
    def setUp(self):
        super(TestScimPasswdUpdateGetter, self).setUp()
        self.config = {
            "path_username": "userName",
            "path_uid": "id",
            "path_gid": "id",
            "path_home_directory": "homeDirectory",
            "path_login_shell": "loginShell"
        }
        self.updater = scimsource.PasswdUpdateGetter(self.config)

    def testGetParser(self):
        """Test that GetParser returns correct parser type."""
        self.updater.source = mock.Mock()
        parser = self.updater.GetParser()
        self.assertTrue(isinstance(parser, scimsource.ScimPasswdMapParser))

    def testCreateMap(self):
        """Test that CreateMap returns PasswdMap."""
        passwd_map = self.updater.CreateMap()
        self.assertTrue(isinstance(passwd_map, passwd.PasswdMap))

    def testCreateMapMissingRequiredConfig(self):
        """Test that CreateMap raises error when required config is missing."""
        incomplete_config = {"path_username": "userName"}
        updater = scimsource.PasswdUpdateGetter(incomplete_config)
        
        with self.assertRaises(error.ConfigurationError) as cm:
            updater.CreateMap()
        
        self.assertIn("required for the passwd map", str(cm.exception))


class TestScimGroupUpdateGetter(unittest.TestCase):
    def setUp(self):
        super(TestScimGroupUpdateGetter, self).setUp()
        self.config = {"path_gid": "id"}
        self.updater = scimsource.GroupUpdateGetter(self.config)

    def testGetParser(self):
        """Test that GetParser returns correct parser type."""
        self.updater.source = mock.Mock()
        parser = self.updater.GetParser()
        self.assertTrue(isinstance(parser, scimsource.ScimGroupMapParser))

    def testCreateMap(self):
        """Test that CreateMap returns GroupMap."""
        group_map = self.updater.CreateMap()
        self.assertTrue(isinstance(group_map, group.GroupMap))

    def testCreateMapMissingRequiredConfig(self):
        """Test that CreateMap raises error when required config is missing."""
        incomplete_config = {}
        updater = scimsource.GroupUpdateGetter(incomplete_config)
        
        with self.assertRaises(error.ConfigurationError) as cm:
            updater.CreateMap()
        
        self.assertIn("scim_path_gid configuration is required", str(cm.exception))


class TestScimSshkeyUpdateGetter(unittest.TestCase):
    def setUp(self):
        super(TestScimSshkeyUpdateGetter, self).setUp()
        self.config = {"path_ssh_keys": "sshKeys"}
        self.updater = scimsource.SshkeyUpdateGetter(self.config)

    def testGetParser(self):
        """Test that GetParser returns correct parser type."""
        self.updater.source = mock.Mock()
        parser = self.updater.GetParser()
        self.assertTrue(isinstance(parser, scimsource.ScimSshkeyMapParser))

    def testCreateMap(self):
        """Test that CreateMap returns SshkeyMap."""
        sshkey_map = self.updater.CreateMap()
        self.assertTrue(isinstance(sshkey_map, sshkey.SshkeyMap))

    def testCreateMapMissingRequiredConfig(self):
        """Test that CreateMap raises error when required config is missing."""
        incomplete_config = {}
        updater = scimsource.SshkeyUpdateGetter(incomplete_config)
        
        with self.assertRaises(error.ConfigurationError) as cm:
            updater.CreateMap()
        
        self.assertIn("scim_path_ssh_keys configuration is required", str(cm.exception))


class TestScimMapParser(unittest.TestCase):
    def setUp(self):
        super(TestScimMapParser, self).setUp()
        self.mock_source = mock.Mock()
        self.mock_source.conf = {
            "path_username": "userName",
            "scim_path_uid": "id"
        }
        self.parser = scimsource.ScimMapParser(self.mock_source)

    def testGetMapConfig(self):
        """Test _GetMapConfig method."""
        # Test stripped key lookup
        result = self.parser._GetMapConfig("scim_path_username", "default")
        self.assertEqual(result, "userName")
        
        # Test exact key lookup
        result = self.parser._GetMapConfig("scim_path_uid", "default")
        self.assertEqual(result, "id")
        
        # Test default value
        result = self.parser._GetMapConfig("nonexistent_key", "default")
        self.assertEqual(result, "default")

    def testExtractFromPath(self):
        """Test _ExtractFromPath method."""
        data = {
            "userName": "testuser",
            "name": {
                "givenName": "Test",
                "familyName": "User"
            }
        }
        
        # Test simple path
        result = self.parser._ExtractFromPath(data, "userName")
        self.assertEqual(result, "testuser")
        
        # Test nested path
        result = self.parser._ExtractFromPath(data, "name/givenName")
        self.assertEqual(result, "Test")
        
        # Test nonexistent path
        result = self.parser._ExtractFromPath(data, "nonexistent", "default")
        self.assertEqual(result, "default")

    def testGetMapWithValidJson(self):
        """Test GetMap with valid SCIM JSON response."""
        scim_response = {
            "Resources": [
                {"id": "1", "userName": "user1"},
                {"id": "2", "userName": "user2"}
            ]
        }
        
        mock_cache_info = mock.Mock()
        mock_cache_info.read.return_value = json.dumps(scim_response)
        
        mock_data = mock.Mock()
        mock_data.Add.return_value = True
        mock_data.__len__ = mock.Mock(return_value=2)
        
        # Mock _ReadEntry to return mock entries
        self.parser._ReadEntry = mock.Mock(side_effect=[mock.Mock(), mock.Mock()])
        
        result = self.parser.GetMap(mock_cache_info, mock_data)
        
        self.assertEqual(result, mock_data)
        self.assertEqual(self.parser._ReadEntry.call_count, 2)

    def testGetMapWithInvalidJson(self):
        """Test GetMap with invalid JSON response."""
        mock_cache_info = mock.Mock()
        mock_cache_info.read.return_value = "invalid json"
        
        mock_data = mock.Mock()
        mock_data.__len__ = mock.Mock(return_value=0)
        
        result = self.parser.GetMap(mock_cache_info, mock_data)
        
        self.assertEqual(result, mock_data)


class TestScimPasswdMapParser(unittest.TestCase):
    def setUp(self):
        super(TestScimPasswdMapParser, self).setUp()
        self.mock_source = mock.Mock()
        self.mock_source.conf = {
            "path_username": "userName",
            "path_uid": "id",
            "path_gid": "id",
            "path_home_directory": "homeDirectory",
            "path_login_shell": "loginShell"
        }
        self.parser = scimsource.ScimPasswdMapParser(self.mock_source)

    def testReadEntryValidUser(self):
        """Test _ReadEntry with valid user data."""
        user_data = {
            "id": "1001",
            "userName": "testuser",
            "homeDirectory": "/home/testuser",
            "loginShell": "/bin/bash",
            "name": {"formatted": "Test User"}
        }
        
        entry = self.parser._ReadEntry(user_data)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.name, "testuser")
        self.assertEqual(entry.uid, 1001)
        self.assertEqual(entry.gid, 1001)  # Should default to UID
        self.assertEqual(entry.dir, "/home/testuser")
        self.assertEqual(entry.shell, "/bin/bash")
        self.assertEqual(entry.gecos, "Test User")

    def testReadEntryMissingUsername(self):
        """Test _ReadEntry with missing username."""
        user_data = {"id": "1001"}
        
        entry = self.parser._ReadEntry(user_data)
        
        self.assertIsNone(entry)

    def testReadEntryMissingUid(self):
        """Test _ReadEntry with missing UID."""
        user_data = {"userName": "testuser"}
        
        entry = self.parser._ReadEntry(user_data)
        
        self.assertIsNone(entry)


class TestScimSshkeyMapParser(unittest.TestCase):
    def setUp(self):
        super(TestScimSshkeyMapParser, self).setUp()
        self.mock_source = mock.Mock()
        self.mock_source.conf = {
            "path_username": "userName",
            "path_ssh_keys": "sshKeys"
        }
        self.parser = scimsource.ScimSshkeyMapParser(self.mock_source)

    def testReadEntryWithSshKeys(self):
        """Test _ReadEntry with SSH keys."""
        user_data = {
            "userName": "testuser",
            "sshKeys": [
                "ssh-rsa AAAAB3NzaC1yc2EAAAA... user@host1",
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... user@host2"
            ]
        }
        
        entries = self.parser._ReadEntry(user_data)
        
        self.assertEqual(len(entries), 2)
        for entry in entries:
            self.assertEqual(entry.name, "testuser")
            self.assertTrue(entry.sshkey.startswith("ssh-"))

    def testReadEntryNoSshKeysPath(self):
        """Test _ReadEntry when SSH keys path is not configured."""
        self.mock_source.conf = {"path_username": "userName"}
        parser = scimsource.ScimSshkeyMapParser(self.mock_source)
        
        user_data = {"userName": "testuser"}
        
        entries = parser._ReadEntry(user_data)
        
        self.assertEqual(len(entries), 0)


class TestScimGroupMapParser(unittest.TestCase):
    def setUp(self):
        super(TestScimGroupMapParser, self).setUp()
        self.mock_source = mock.Mock()
        self.mock_source.conf = {
            "path_gid": "id",
            "path_username": "members/value"
        }
        self.parser = scimsource.ScimGroupMapParser(self.mock_source)

    def testReadEntryValidGroup(self):
        """Test _ReadEntry with valid group data."""
        group_data = {
            "id": "2001",
            "displayName": "testgroup",
            "members": [
                {"value": "user1"},
                {"value": "user2"}
            ]
        }
        
        entry = self.parser._ReadEntry(group_data)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.name, "testgroup")
        self.assertEqual(entry.gid, 2001)
        self.assertEqual(entry.members, ["user1", "user2"])

    def testReadEntryMissingGid(self):
        """Test _ReadEntry with missing GID."""
        group_data = {"displayName": "testgroup"}
        
        entry = self.parser._ReadEntry(group_data)
        
        self.assertIsNone(entry)


if __name__ == "__main__":
    unittest.main()
