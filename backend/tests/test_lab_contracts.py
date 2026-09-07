from unittest.mock import Mock, patch

from utils.auth_session import create_authenticated_session
from agents.pentest_agent import _check_directory_listing


def test_login_requires_explicit_success_evidence():
    session = Mock()
    session.cookies = {}
    session.get.return_value = Mock(status_code=200, text='<form>Login</form>')
    session.post.return_value = Mock(status_code=200, text='<form>Login</form>')
    with patch('utils.auth_session.get_session', return_value=session):
        assert create_authenticated_session('http://localhost:8080/login.php', 'admin', 'password') is None
    session.close.assert_called_once()


def test_login_indicator_must_be_new_after_authentication():
    session = Mock()
    session.cookies = {}
    session.get.return_value = Mock(status_code=200, text='Logout is shown on this public help page')
    session.post.return_value = Mock(status_code=200, text='Logout is shown on this public help page')
    with patch('utils.auth_session.get_session', return_value=session):
        assert create_authenticated_session('http://localhost:8080/login.php', 'admin', 'password', success_indicator='Logout') is None
    session.close.assert_called_once()


def test_directory_listing_all_probe_failures_are_not_a_clean_result():
    with patch('agents.pentest_agent._probe_get', return_value=(None, 'connection refused')):
        finding = _check_directory_listing('http://localhost:8080')
    assert finding.check_status == 'UNREACHABLE'


def test_directory_listing_partial_probe_failure_is_incomplete():
    good = Mock(status_code=200, text='<html>Ordinary page</html>')
    with patch('agents.pentest_agent._probe_get', side_effect=[(good, '')]+[(None, 'timeout')]*50):
        finding = _check_directory_listing('http://localhost:8080')
    assert finding.check_status == 'INCOMPLETE'


def test_verified_login_returns_open_session():
    session = Mock()
    session.cookies = {}
    session.get.return_value = Mock(status_code=200, text='<form>Login</form>')
    session.post.return_value = Mock(status_code=200, text='<a href="logout.php">Logout</a>')
    with patch('utils.auth_session.get_session', return_value=session):
        assert create_authenticated_session('http://localhost:8080/login.php', 'admin', 'password', success_indicator='Logout') is session
    session.close.assert_not_called()


def test_directory_listing_positive_evidence_survives_partial_failure():
    listing = Mock(status_code=200, text='<title>Index of /files</title>')
    with patch('agents.pentest_agent._probe_get', side_effect=[(listing, '')]+[(None, 'timeout')]*50):
        finding = _check_directory_listing('http://localhost:8080')
    assert finding.check_status == 'VULNERABLE'
