from onionshare_cli import common, meek, onion


class FakeSettings:
    def set(self, key, value):
        raise AssertionError("existing built-in bridges should remain unchanged")

    def save(self):
        raise AssertionError("unchanged bridge settings should not be saved")


class FakeCensorshipCircumvention:
    def __init__(self, common_obj, meek_obj, onion_obj):
        pass

    def request_builtin_bridges(self):
        return False


class MissingMeek:
    def __init__(self, common_obj):
        self.common = common_obj

    def start(self):
        raise meek.MeekNotFound(self.common)


def test_update_builtin_bridges_keeps_existing_bridges_when_meek_is_missing(
    monkeypatch,
):
    common_obj = common.Common()
    onion_obj = onion.Onion(common_obj, get_tor_paths=lambda: (None,) * 7)
    onion_obj.settings = FakeSettings()
    onion_obj.is_authenticated = lambda: False

    monkeypatch.setattr(onion, "CensorshipCircumvention", FakeCensorshipCircumvention)
    monkeypatch.setattr(onion, "Meek", MissingMeek)

    assert onion_obj.update_builtin_bridges() is False
