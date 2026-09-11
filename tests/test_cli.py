import json
import pytest
from threatintel.cli import main

def test_cli(tmp_path, capsys):
    data = [
        {
            "type": "domain",
            "value": "EVIL.COM.",
            "source": "feed_a",
        },
        {
            "type": "domain",
            "value": "evil.com",
            "source": "feed_b",
        },
        {
            "type": "ip",
            "value": "192.168.1.10",
            "source": "feed_a",
        },
        {
            "type": "sha256",
            "value": "A" * 64,
            "source": "feed_c",
        }
    ]

    path = tmp_path / "iocs.json"
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file)

    main([str(path)])

    captured = capsys.readouterr()
    expected_text = "Indicators processed: 4\nUnique indicators: 3\nDuplicates: 1\n\nip: 1\ndomain: 1\nsha256: 1\n"

    assert captured.out == expected_text


def test_cli_empty(tmp_path, capsys):
    data = []
    path = tmp_path / "iocs.json"
    with open(path, "w", encoding="utf-8") as file:
        json.dump(data, file)

    main([str(path)])

    captured = capsys.readouterr()
    expected_text = "Indicators processed: 0\nUnique indicators: 0\nDuplicates: 0\n\nip: 0\ndomain: 0\nsha256: 0\n"

    assert captured.out == expected_text

def test_cli_no_filename():
    with pytest.raises(SystemExit) as exception:
        main([])
    assert exception.value.code == 2