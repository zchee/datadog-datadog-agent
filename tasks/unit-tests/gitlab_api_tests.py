import socket
import unittest

from invoke import Context
from invoke.exceptions import Exit

from tasks.libs.ciproviders.gitlab_api import generate_gitlab_full_configuration, read_includes
from tasks.libs.common.color import color_message
from tasks.pre_commit import check_gitlab_access


class TestReadIncludes(unittest.TestCase):
    def test_with_includes(self):
        includes = []
        read_includes("tasks/unit-tests/testdata/in.yml", includes)
        self.assertEqual(len(includes), 4)

    def test_without_includes(self):
        includes = []
        read_includes("tasks/unit-tests/testdata/b.yml", includes)
        self.assertEqual(len(includes), 1)


class TestGenerateGitlabFullConfiguration(unittest.TestCase):
    def test_nominal(self):
        full_configuration = generate_gitlab_full_configuration("tasks/unit-tests/testdata/in.yml")
        with open("tasks/unit-tests/testdata/out.yml") as f:
            expected = f.read()
        self.assertEqual(full_configuration, expected)

    def test_yaml_with_reference(self):
        full_configuration = generate_gitlab_full_configuration(
            "tasks/unit-tests/testdata/ci_config_with_reference.yml"
        )
        with open("tasks/unit-tests/testdata/expected.yml") as f:
            expected = f.read()
        self.assertEqual(full_configuration, expected)


class TestGitlabYaml(unittest.TestCase):
    def make_test(self, file):
        config = generate_gitlab_full_configuration(file, return_dump=False, apply_postprocessing=True)

        self.assertDictEqual(config['target'], config['expected'])

    def test_reference(self):
        self.make_test("tasks/unit-tests/testdata/yaml_reference.yml")

    def test_extends(self):
        self.make_test("tasks/unit-tests/testdata/yaml_extends.yml")

    def test_extends_reference(self):
        self.make_test("tasks/unit-tests/testdata/yaml_extends_reference.yml")


class TestGitlabAccess(unittest.TestCase):
    getaddrinfo_values = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('172.27.1.237', 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('172.27.0.123', 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('172.27.5.181', 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('172.27.2.234', 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('172.27.33.44', 443)),
        (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('172.27.77.88', 443)),
    ]

    @unittest.mock.patch('tasks.pre_commit.socket.getaddrinfo')
    @unittest.mock.patch('tasks.pre_commit.socket.socket.connect')
    def test_no_gitlab_access(self, mock_connect, mock_getaddrinfo):
        mock_connect.side_effect = [TimeoutError, TimeoutError, TimeoutError, TimeoutError, TimeoutError, TimeoutError]
        mock_getaddrinfo.return_value = self.getaddrinfo_values
        expected_msg = color_message(
            "\nConnections to gitlab.ddbuild.io all timed out. Are you connected to Appgate?", color="red"
        )

        with self.assertRaises(Exit) as cm:
            check_gitlab_access(Context())
        exception = cm.exception

        self.assertEqual(mock_connect.call_count, 4)
        self.assertEqual(exception.message, expected_msg)
        self.assertEqual(exception.code, 1)

    @unittest.mock.patch('tasks.pre_commit.socket.getaddrinfo')
    @unittest.mock.patch('tasks.pre_commit.socket.socket.connect')
    def test_unstable_gitlab_access(self, mock_connect, mock_getaddrinfo):
        mock_connect.side_effect = [TimeoutError, None, None, None]
        mock_getaddrinfo.return_value = self.getaddrinfo_values[:4]
        result = check_gitlab_access(Context())
        self.assertEqual(mock_connect.call_count, 2)
        self.assertIsNone(result)
