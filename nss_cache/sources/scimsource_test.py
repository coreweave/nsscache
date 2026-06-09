"""Unit tests for SCIM data source for nsscache."""

import json
import os
import unittest
import pycurl
from unittest import mock

from nss_cache import error
from nss_cache.maps import group
from nss_cache.maps import passwd
from nss_cache.maps import shadow
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

    def testBuildUrlWithParameters(self):
        """Test that URL parameters are properly handled."""
        config = {
            "base_url": "https://api.example.com/scim",
            "auth_token": "test_token"
        }
        source = scimsource.ScimSource(config)
        
        # Test with no parameters
        url = source._BuildUrlWithParameters("https://api.example.com/scim/Users", "")
        self.assertEqual(url, "https://api.example.com/scim/Users")
        
        # Test with simple parameters (comma gets URL encoded)
        url = source._BuildUrlWithParameters("https://api.example.com/scim/Users", "groups=users,admin")
        self.assertEqual(url, "https://api.example.com/scim/Users?groups=users%2Cadmin")
        
        # Test with parameters that have leading ? or &
        url = source._BuildUrlWithParameters("https://api.example.com/scim/Users", "?groups=users,admin")
        self.assertEqual(url, "https://api.example.com/scim/Users?groups=users%2Cadmin")
        
        url = source._BuildUrlWithParameters("https://api.example.com/scim/Users", "&groups=users,admin")
        self.assertEqual(url, "https://api.example.com/scim/Users?groups=users%2Cadmin")
        
        # Test with complex SCIM filter that needs encoding
        url = source._BuildUrlWithParameters("https://api.example.com/scim/Groups", 'filter=displayName eq "users"')
        self.assertEqual(url, "https://api.example.com/scim/Groups?filter=displayName+eq+%22users%22")
        
        # Test with multiple parameters
        url = source._BuildUrlWithParameters("https://api.example.com/scim/Users", "groups=admin,metrics&filter=active eq \"true\"")
        self.assertEqual(url, "https://api.example.com/scim/Users?groups=admin%2Cmetrics&filter=active+eq+%22true%22")

    def testParametersConfiguration(self):
        """Test that users_parameters and groups_parameters are configured properly."""
        config = {
            "base_url": "https://api.example.com/scim",
            "auth_token": "test_token",
            "users_parameters": "groups=users,admin&filter=active",
            "groups_parameters": "type=security"
        }
        source = scimsource.ScimSource(config)
        
        self.assertEqual(source.conf["users_parameters"], "groups=users,admin&filter=active")
        self.assertEqual(source.conf["groups_parameters"], "type=security")

    def testParametersDefaultsToEmpty(self):
        """Test that parameters default to empty strings."""
        config = {
            "base_url": "https://api.example.com/scim",
            "auth_token": "test_token"
        }
        source = scimsource.ScimSource(config)
        
        self.assertEqual(source.conf["users_parameters"], "")
        self.assertEqual(source.conf["groups_parameters"], "")


class TestScimUpdateGetter(unittest.TestCase):
    def setUp(self):
        super().setUp()
        curl_patcher = mock.patch.object(pycurl, "Curl")
        self.addCleanup(curl_patcher.stop)
        self.curl_mock = curl_patcher.start()

    def testGetUpdatesWithPagination(self):
        """Test that pagination works correctly by reading from SCIM response."""
        mock_conn = mock.Mock()
        mock_conn.getinfo.return_value = 200
        self.curl_mock.return_value = mock_conn
        
        config = {
            "base_url": "https://api.example.com/scim",
            "auth_token": "test_token"
        }
        source = scimsource.ScimSource(config)
        
        # Mock the first page response with pagination info
        first_page_response = {
            "totalResults": 75,
            "itemsPerPage": 50,
            "startIndex": 1,
            "Resources": [{"id": str(i), "userName": f"user{i}"} for i in range(1, 51)]
        }
        
        # Mock the second page response
        second_page_response = {
            "totalResults": 75,
            "itemsPerPage": 25,
            "startIndex": 51,
            "Resources": [{"id": str(i), "userName": f"user{i}"} for i in range(51, 76)]
        }
        
        with mock.patch.object(curl, 'CurlFetch') as mock_curl_fetch:
            mock_curl_fetch.side_effect = [
                (200, "", json.dumps(first_page_response).encode('utf-8')),
                (200, "", json.dumps(second_page_response).encode('utf-8'))
            ]
            
            getter = scimsource.UpdateGetter()
            getter.source = source
            
            # Mock the parser and its pagination metadata
            mock_parser = mock.Mock()
            
            # Mock the first map returned by GetMap 
            mock_first_map = mock.Mock()
            mock_first_map.__len__ = mock.Mock(return_value=50)
            
            # Mock the second map returned by GetMap
            mock_second_map = mock.Mock()
            mock_second_map.__len__ = mock.Mock(return_value=75)  # Total items after both pages
            
            # Track which call we're on
            call_count = 0
            
            # Configure GetMap to return the mocked maps and update pagination metadata
            def mock_get_map(cache_info, data):
                nonlocal call_count
                call_count += 1
                
                if call_count == 1:
                    # First page
                    mock_parser._pagination_metadata = {
                        'totalResults': 75,
                        'itemsPerPage': 50,
                        'startIndex': 1
                    }
                    return mock_first_map
                else:
                    # Second page  
                    mock_parser._pagination_metadata = {
                        'totalResults': 75,
                        'itemsPerPage': 25,
                        'startIndex': 51
                    }
                    return mock_second_map
            
            mock_parser.GetMap = mock.Mock(side_effect=mock_get_map)
            
            getter.GetParser = mock.Mock(return_value=mock_parser)
            getter.CreateMap = mock.Mock(return_value=mock.Mock())
            
            result = getter.GetUpdates(source, "https://api.example.com/scim/Users", None)
            
            # Should call CurlFetch twice (first page + second page)
            self.assertEqual(mock_curl_fetch.call_count, 2)
            
            # Should call GetMap twice (first page + second page)  
            self.assertEqual(mock_parser.GetMap.call_count, 2)
            
            # Verify the URLs include pagination parameters
            call_args = mock_curl_fetch.call_args_list
            self.assertIn("Users", call_args[0][0][0])  # First call should be to base URL
            self.assertIn("startIndex=51", call_args[1][0][0])  # Second call should have pagination

    def testGetUpdatesWithPaginationAndCustomParameters(self):
        """Test that pagination works correctly with custom URL parameters."""
        mock_conn = mock.Mock()
        mock_conn.getinfo.return_value = 200
        self.curl_mock.return_value = mock_conn
        
        config = {
            "base_url": "https://api.example.com/scim",
            "auth_token": "test_token"
        }
        source = scimsource.ScimSource(config)
        
        # Mock the first page response with pagination info
        first_page_response = {
            "totalResults": 75,
            "itemsPerPage": 50,
            "startIndex": 1,
            "Resources": [{"id": str(i), "userName": f"user{i}"} for i in range(1, 51)]
        }
        
        # Mock the second page response
        second_page_response = {
            "totalResults": 75,
            "itemsPerPage": 25,
            "startIndex": 51,
            "Resources": [{"id": str(i), "userName": f"user{i}"} for i in range(51, 76)]
        }
        
        with mock.patch.object(curl, 'CurlFetch') as mock_curl_fetch:
            mock_curl_fetch.side_effect = [
                (200, "", json.dumps(first_page_response).encode('utf-8')),
                (200, "", json.dumps(second_page_response).encode('utf-8'))
            ]
            
            getter = scimsource.UpdateGetter()
            getter.source = source
            
            # Mock the parser and its pagination metadata
            mock_parser = mock.Mock()
            
            # Mock the first map returned by GetMap 
            mock_first_map = mock.Mock()
            mock_first_map.__len__ = mock.Mock(return_value=50)
            
            # Mock the second map returned by GetMap
            mock_second_map = mock.Mock()
            mock_second_map.__len__ = mock.Mock(return_value=75)  # Total items after both pages
            
            # Track which call we're on
            call_count = 0
            
            # Configure GetMap to return the mocked maps and update pagination metadata
            def mock_get_map(cache_info, data):
                nonlocal call_count
                call_count += 1
                
                if call_count == 1:
                    # First page
                    mock_parser._pagination_metadata = {
                        'totalResults': 75,
                        'itemsPerPage': 50,
                        'startIndex': 1
                    }
                    return mock_first_map
                else:
                    # Second page  
                    mock_parser._pagination_metadata = {
                        'totalResults': 75,
                        'itemsPerPage': 25,
                        'startIndex': 51
                    }
                    return mock_second_map
            
            mock_parser.GetMap = mock.Mock(side_effect=mock_get_map)
            
            getter.GetParser = mock.Mock(return_value=mock_parser)
            getter.CreateMap = mock.Mock(return_value=mock.Mock())
            
            # Test with URL that has custom parameters
            result = getter.GetUpdates(source, "https://api.example.com/scim/Users?groups=users,admin", None)
            
            # Should call CurlFetch twice (first page + second page)
            self.assertEqual(mock_curl_fetch.call_count, 2)
            
            # Should call GetMap twice (first page + second page)  
            self.assertEqual(mock_parser.GetMap.call_count, 2)
            
            # Verify the URLs include both custom parameters and pagination parameters
            call_args = mock_curl_fetch.call_args_list
            # First call should include custom parameters and startIndex=1
            self.assertIn("groups=users,admin", call_args[0][0][0])
            self.assertIn("startIndex=1", call_args[0][0][0])
            
            # Second call should include custom parameters and startIndex=51
            self.assertIn("groups=users,admin", call_args[1][0][0])
            self.assertIn("startIndex=51", call_args[1][0][0])

    def testGetUpdatesWithCursorPagination(self):
        """Cursor pagination walks pages off `nextCursor` until it's omitted."""
        mock_conn = mock.Mock()
        mock_conn.getinfo.return_value = 200
        self.curl_mock.return_value = mock_conn

        config = {
            "base_url": "https://api.example.com/scim",
            "auth_token": "test_token"
        }
        source = scimsource.ScimSource(config)

        # Three pages of one user each. The first two responses carry a
        # `nextCursor`; the third omits it to signal completion.
        page_responses = [
            {
                "Resources": [{"id": "1", "userName": "user1"}],
                "nextCursor": "token-page-2",
            },
            {
                "Resources": [{"id": "2", "userName": "user2"}],
                "nextCursor": "token-page-3",
            },
            {
                "Resources": [{"id": "3", "userName": "user3"}],
            },
        ]

        with mock.patch.object(curl, 'CurlFetch') as mock_curl_fetch:
            mock_curl_fetch.side_effect = [
                (200, "", json.dumps(resp).encode('utf-8'))
                for resp in page_responses
            ]

            getter = scimsource.UpdateGetter()
            getter.source = source

            mock_parser = mock.Mock()
            mock_map = mock.Mock()
            mock_map.__len__ = mock.Mock(return_value=3)

            call_count = 0

            def mock_get_map(cache_info, data):
                nonlocal call_count
                response = page_responses[call_count]
                call_count += 1
                mock_parser._pagination_metadata = {
                    'totalResults': 0,
                    'itemsPerPage': 0,
                    'startIndex': 1,
                    'nextCursor': response.get('nextCursor'),
                }
                return mock_map

            mock_parser.GetMap = mock.Mock(side_effect=mock_get_map)
            getter.GetParser = mock.Mock(return_value=mock_parser)
            getter.CreateMap = mock.Mock(return_value=mock.Mock())

            getter.GetUpdates(source, "https://api.example.com/scim/Users?count=1&cursor=", None)

            self.assertEqual(mock_curl_fetch.call_count, 3)
            self.assertEqual(mock_parser.GetMap.call_count, 3)

            call_args = mock_curl_fetch.call_args_list
            # First request is the original URL — cursor= with no token.
            self.assertIn("cursor=", call_args[0][0][0])
            self.assertNotIn("cursor=token-", call_args[0][0][0])

            # Subsequent requests carry the cursor returned by the prior page.
            self.assertIn("cursor=token-page-2", call_args[1][0][0])
            self.assertIn("cursor=token-page-3", call_args[2][0][0])

            # startIndex must never be appended in cursor mode.
            for call in call_args:
                self.assertNotIn("startIndex=", call[0][0])

    def testGetUpdatesWithCursorPaginationSinglePage(self):
        """When the first cursor response omits `nextCursor`, stop after one fetch."""
        mock_conn = mock.Mock()
        mock_conn.getinfo.return_value = 200
        self.curl_mock.return_value = mock_conn

        config = {
            "base_url": "https://api.example.com/scim",
            "auth_token": "test_token"
        }
        source = scimsource.ScimSource(config)

        single_page_response = {
            "Resources": [{"id": "1", "userName": "user1"}],
        }

        with mock.patch.object(curl, 'CurlFetch') as mock_curl_fetch:
            mock_curl_fetch.side_effect = [
                (200, "", json.dumps(single_page_response).encode('utf-8'))
            ]

            getter = scimsource.UpdateGetter()
            getter.source = source

            mock_parser = mock.Mock()
            mock_map = mock.Mock()
            mock_map.__len__ = mock.Mock(return_value=1)

            def mock_get_map(cache_info, data):
                mock_parser._pagination_metadata = {
                    'totalResults': 0,
                    'itemsPerPage': 0,
                    'startIndex': 1,
                    'nextCursor': None,
                }
                return mock_map

            mock_parser.GetMap = mock.Mock(side_effect=mock_get_map)
            getter.GetParser = mock.Mock(return_value=mock_parser)
            getter.CreateMap = mock.Mock(return_value=mock.Mock())

            getter.GetUpdates(source, "https://api.example.com/scim/Users?cursor=", None)

            self.assertEqual(mock_curl_fetch.call_count, 1)
            self.assertEqual(mock_parser.GetMap.call_count, 1)

    def testGetUpdatesWithCursorPreservesCustomParams(self):
        """Cursor rewrites preserve other query parameters across requests."""
        mock_conn = mock.Mock()
        mock_conn.getinfo.return_value = 200
        self.curl_mock.return_value = mock_conn

        config = {
            "base_url": "https://api.example.com/scim",
            "auth_token": "test_token"
        }
        source = scimsource.ScimSource(config)

        page_responses = [
            {
                "Resources": [{"id": "1", "userName": "user1"}],
                "nextCursor": "next-token",
            },
            {
                "Resources": [{"id": "2", "userName": "user2"}],
            },
        ]

        with mock.patch.object(curl, 'CurlFetch') as mock_curl_fetch:
            mock_curl_fetch.side_effect = [
                (200, "", json.dumps(resp).encode('utf-8'))
                for resp in page_responses
            ]

            getter = scimsource.UpdateGetter()
            getter.source = source

            mock_parser = mock.Mock()
            mock_map = mock.Mock()
            mock_map.__len__ = mock.Mock(return_value=2)

            call_count = 0

            def mock_get_map(cache_info, data):
                nonlocal call_count
                response = page_responses[call_count]
                call_count += 1
                mock_parser._pagination_metadata = {
                    'totalResults': 0,
                    'itemsPerPage': 0,
                    'startIndex': 1,
                    'nextCursor': response.get('nextCursor'),
                }
                return mock_map

            mock_parser.GetMap = mock.Mock(side_effect=mock_get_map)
            getter.GetParser = mock.Mock(return_value=mock_parser)
            getter.CreateMap = mock.Mock(return_value=mock.Mock())

            # Pass an already-encoded filter (matching what _BuildUrlWithParameters
            # produces at the source call site).
            initial_url = 'https://api.example.com/scim/Users?filter=active+eq+%22true%22&cursor='
            getter.GetUpdates(source, initial_url, None)

            self.assertEqual(mock_curl_fetch.call_count, 2)

            call_args = mock_curl_fetch.call_args_list
            # The second request must keep the filter param alongside the new cursor.
            second_url = call_args[1][0][0]
            self.assertIn("filter=", second_url)
            self.assertIn("active", second_url)
            self.assertIn("cursor=next-token", second_url)


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


class TestScimShadowUpdateGetter(unittest.TestCase):
    def setUp(self):
        super(TestScimShadowUpdateGetter, self).setUp()
        self.config = {"path_username": "userName"}
        self.updater = scimsource.ShadowUpdateGetter(self.config)

    def testGetParser(self):
        """Test that GetParser returns correct parser type."""
        self.updater.source = mock.Mock()
        parser = self.updater.GetParser()
        self.assertTrue(isinstance(parser, scimsource.ScimShadowMapParser))

    def testCreateMap(self):
        """Test that CreateMap returns ShadowMap."""
        shadow_map = self.updater.CreateMap()
        self.assertTrue(isinstance(shadow_map, shadow.ShadowMap))


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
        self.assertEqual(entry.gid, 1001)
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

    def testReadEntryWithHomeDirectoryOverride(self):
        """Test _ReadEntry with home directory override."""
        self.mock_source.conf.update({
            "override_home_directory": "/mnt/home/%u"
        })
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
        self.assertEqual(entry.dir, "/mnt/home/testuser")  # Should use override with %u substitution

    def testReadEntryWithHomeDirectoryOverrideNoSubstitution(self):
        """Test _ReadEntry with home directory override without %u substitution."""
        self.mock_source.conf.update({
            "override_home_directory": "/shared/home"
        })
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
        self.assertEqual(entry.dir, "/shared/home")  # Should use override as-is without substitution


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
        """Test _ReadEntry returns a single entry whose sshkey is the list of keys.

        FilesSshkeyMapHandler._WriteData later serializes ``entry.sshkey`` into
        a single cache line per user, so the parser bundles every key for a
        user into one SshkeyMapEntry rather than fanning out to one entry per
        key.
        """
        ssh_keys = [
            "ssh-rsa AAAAB3NzaC1yc2EAAAA... user@host1",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... user@host2",
        ]
        user_data = {
            "userName": "testuser",
            "sshKeys": ssh_keys,
        }

        entries = self.parser._ReadEntry(user_data)

        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.name, "testuser")
        self.assertEqual(entry.sshkey, ssh_keys)

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

    def testReadEntryWithNestedMemberPath(self):
        """Test _ReadEntry with nested member path like 'members/username'."""
        self.mock_source.conf["path_username"] = "members/username"
        
        group_data = {
            "id": "2003",
            "displayName": "testgroup3",
            "members": [
                {"username": "user5", "display": "User Five"},
                {"username": "user6", "display": "User Six"}
            ]
        }
        
        entry = self.parser._ReadEntry(group_data)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.name, "testgroup3")
        self.assertEqual(entry.gid, 2003)
        self.assertEqual(entry.members, ["user5", "user6"])

    def testReadEntryWithSimpleMemberPath(self):
        """Test _ReadEntry with simple member path (no slash)."""
        self.mock_source.conf["path_username"] = "userName"
        
        group_data = {
            "id": "2004",
            "displayName": "testgroup4",
            "members": [
                {"userName": "user7"},
                {"userName": "user8"}
            ]
        }
        
        entry = self.parser._ReadEntry(group_data)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.name, "testgroup4")
        self.assertEqual(entry.gid, 2004)
        self.assertEqual(entry.members, ["user7", "user8"])

    def testReadEntryWithStringMembers(self):
        """Test _ReadEntry with string members."""
        self.mock_source.conf["path_username"] = "userName"
        
        group_data = {
            "id": "2005",
            "displayName": "testgroup5",
            "members": ["user9", "user10"]
        }
        
        entry = self.parser._ReadEntry(group_data)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.name, "testgroup5")
        self.assertEqual(entry.gid, 2005)
        self.assertEqual(entry.members, ["user9", "user10"])

    def testReadEntryWithEmptyMembers(self):
        """Test _ReadEntry with empty members array."""
        group_data = {
            "id": "2006",
            "displayName": "testgroup6",
            "members": []
        }
        
        entry = self.parser._ReadEntry(group_data)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.name, "testgroup6")
        self.assertEqual(entry.gid, 2006)
        self.assertEqual(entry.members, [])

    def testReadEntryWithMissingMembers(self):
        """Test _ReadEntry with missing members field."""
        group_data = {
            "id": "2007",
            "displayName": "testgroup7"
        }
        
        entry = self.parser._ReadEntry(group_data)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.name, "testgroup7")
        self.assertEqual(entry.gid, 2007)
        self.assertEqual(entry.members, [])


class TestScimShadowMapParser(unittest.TestCase):
    def setUp(self):
        super(TestScimShadowMapParser, self).setUp()
        self.config = {"path_username": "userName"}
        source = mock.Mock()
        source.conf = self.config
        self.parser = scimsource.ScimShadowMapParser(source)

    def testReadEntryValidUser(self):
        """Test _ReadEntry with valid user data."""
        user_data = {
            "userName": "testuser",
            "id": "1001"
        }
        
        entry = self.parser._ReadEntry(user_data)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.name, "testuser")
        self.assertEqual(entry.passwd, "*")
        # All other shadow fields should be empty strings
        self.assertEqual(entry.lstchg, "")
        self.assertEqual(entry.min, "")
        self.assertEqual(entry.max, "")
        self.assertEqual(entry.warn, "")
        self.assertEqual(entry.inact, "")
        self.assertEqual(entry.expire, "")
        self.assertEqual(entry.flag, "")

    def testReadEntryMissingUsername(self):
        """Test _ReadEntry with missing username field."""
        user_data = {
            "id": "1002"
        }
        
        entry = self.parser._ReadEntry(user_data)
        
        self.assertIsNone(entry)

    def testReadEntryWithCustomUsernamePath(self):
        """Test _ReadEntry with custom username path."""
        custom_config = {"path_username": "urn:scim:schemas:extension:User/userName"}
        source = mock.Mock()
        source.conf = custom_config
        parser = scimsource.ScimShadowMapParser(source)
        
        user_data = {
            "urn:scim:schemas:extension:User": {
                "userName": "customuser"
            },
            "id": "1003"
        }
        
        entry = parser._ReadEntry(user_data)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.name, "customuser")
        self.assertEqual(entry.passwd, "*")

    def testReadEntryWithCustomShadowDefaults(self):
        """Test _ReadEntry with custom shadow field defaults."""
        custom_config = {
            "shadow_default_lstchg": "19000",
            "shadow_default_min": "0", 
            "shadow_default_max": "99999",
            "shadow_default_warn": "7",
            "shadow_default_inact": "30",
            "shadow_default_expire": "20000",
            "shadow_default_flag": "0"
        }
        source = mock.Mock()
        source.conf = custom_config
        parser = scimsource.ScimShadowMapParser(source)
        
        user_data = {
            "userName": "testuser",
            "id": "1001"
        }
        
        entry = parser._ReadEntry(user_data)
        
        self.assertIsNotNone(entry)
        self.assertEqual(entry.name, "testuser")
        self.assertEqual(entry.passwd, "*")
        # Verify custom shadow field defaults are used
        self.assertEqual(entry.lstchg, "19000")
        self.assertEqual(entry.min, "0")
        self.assertEqual(entry.max, "99999")
        self.assertEqual(entry.warn, "7")
        self.assertEqual(entry.inact, "30")
        self.assertEqual(entry.expire, "20000")
        self.assertEqual(entry.flag, "0")

if __name__ == "__main__":
    unittest.main()
