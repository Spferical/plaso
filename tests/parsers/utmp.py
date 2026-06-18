#!/usr/bin/env python3
"""Parser test for utmp files."""

import unittest

from plaso.parsers import utmp

from tests.parsers import test_lib


class UtmpParserTest(test_lib.ParserTestCase):
    """The unit test for utmp parser."""

    def testParseUtmpFile(self):
        """Tests the Parse function on a utmp file."""
        parser = utmp.UtmpParser()
        storage_writer = self._ParseFile(["utmp"], parser)

        number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
            "event_data"
        )
        self.assertEqual(number_of_event_data, 14)

        number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
            "extraction_warning"
        )
        self.assertEqual(number_of_warnings, 0)

        number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
            "recovery_warning"
        )
        self.assertEqual(number_of_warnings, 0)

        expected_event_values = {
            "data_type": "linux:utmp:event",
            "exit_status": 0,
            "hostname": "localhost",
            "ip_address": "0.0.0.0",
            "login_time": "2013-12-13T14:45:09.000000+00:00",
            "logout_time": None,
            "pid": 1115,
            "session_length_nanos": None,
            "session_length_seconds": None,
            "terminal": "tty4",
            "terminal_identifier": 52,
            "type": 6,
            "username": "LOGIN",
            "written_time": "2013-12-13T14:45:09.000000+00:00",
        }

        event_data = storage_writer.GetAttributeContainerByIndex("event_data", 2)
        self.CheckEventData(event_data, expected_event_values)

    def testParseWtmpFile(self):
        """Tests the Parse function on a wtmp file."""
        parser = utmp.UtmpParser()
        storage_writer = self._ParseFile(["wtmp.1"], parser)

        number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
            "event_data"
        )
        self.assertEqual(number_of_event_data, 4)

        number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
            "extraction_warning"
        )
        self.assertEqual(number_of_warnings, 0)

        number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
            "recovery_warning"
        )
        self.assertEqual(number_of_warnings, 0)

        expected_event_values = {
            "data_type": "linux:utmp:event",
            "exit_status": 0,
            "hostname": "10.10.122.1",
            "ip_address": "10.10.122.1",
            "login_time": "2011-12-01T17:36:38.432935+00:00",
            "logout_time": None,
            "pid": 20060,
            "session_length_nanos": None,
            "session_length_seconds": None,
            "terminal": "pts/32",
            "terminal_identifier": 842084211,
            "type": 7,
            "username": "userA",
            "written_time": "2011-12-01T17:36:38.432935+00:00",
        }

        event_data = storage_writer.GetAttributeContainerByIndex("event_data", 3)
        self.CheckEventData(event_data, expected_event_values)

    def testParseWtmpFileSessionLength(self):
        """Tests the Parse function on a wtmp file with session length."""
        parser = utmp.UtmpParser()
        storage_writer = self._ParseFile(["wtmp"], parser)

        number_of_event_data = storage_writer.GetNumberOfAttributeContainers(
            "event_data"
        )
        self.assertEqual(number_of_event_data, 24)

        number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
            "extraction_warning"
        )
        self.assertEqual(number_of_warnings, 0)

        number_of_warnings = storage_writer.GetNumberOfAttributeContainers(
            "recovery_warning"
        )
        self.assertEqual(number_of_warnings, 0)

        expected_event_values = {
            "data_type": "linux:utmp:event",
            "exit_status": 0,
            "hostname": "",
            "ip_address": "0.0.0.0",
            "login_time": "2025-01-27T19:15:53.046622+00:00",
            "logout_time": "2025-01-27T20:27:00.670794+00:00",
            "offset": 3456,
            "pid": 133172,
            "session_length_nanos": 624172,
            "session_length_seconds": 4267,
            "terminal": "pts/0",
            "terminal_identifier": 0,
            "type": 8,
            "username": "iokoro_google_com",
            "written_time": "2025-01-27T20:27:00.670794+00:00",
        }

        event_data = storage_writer.GetAttributeContainerByIndex("event_data", 7)
        self.CheckEventData(event_data, expected_event_values)

        # Additional checks for new logic
        all_events = []
        for i in range(number_of_event_data):
            event = storage_writer.GetAttributeContainerByIndex("event_data", i)
            all_events.append(event)

        # DEAD_PROCESS (logoff) events should not have hostname "localhost"
        user_logoff_events_count = 0
        for e in all_events:
            if e.type == 8:  # DEAD_PROCESS
                user_logoff_events_count += 1
                self.assertNotEqual(getattr(e, "hostname", None), "localhost")
        self.assertGreater(user_logoff_events_count, 0)


if __name__ == "__main__":
    unittest.main()
