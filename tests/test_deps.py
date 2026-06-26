"""Test dependency checking."""

from canary_scan.lib.deps import check_dependencies


def test_check_returns_dict():
    status = check_dependencies()
    assert "found" in status
    assert "missing_required" in status
    assert "missing_optional" in status
    assert isinstance(status["found"], list)


def test_strict_promotes_optional():
    normal = check_dependencies(strict=False)
    strict = check_dependencies(strict=True)
    assert len(strict["missing_required"]) >= len(normal["missing_required"])


def test_specialized_includes_extra():
    normal = check_dependencies(enable_specialized=False)
    specialized = check_dependencies(enable_specialized=True)
    specialized_names = {
        d.name for d in specialized["found"] + specialized["missing_required"] + specialized["missing_optional"]
    }
    assert "ffprobe" in specialized_names or "fonttools" in specialized_names
    normal_names = {d.name for d in normal["found"] + normal["missing_required"] + normal["missing_optional"]}
    assert "ffprobe" not in normal_names


def test_parse_hint():
    from canary_scan.lib.deps import parse_hint

    # Tagged cases
    assert parse_hint("[apt|rpm|apk] libimage-exiftool-perl") == ("apt|rpm|apk", "libimage-exiftool-perl")
    assert parse_hint("[pip] peepdf") == ("pip", "peepdf")
    assert parse_hint("[build] build from source") == ("build", "build from source")
    assert parse_hint("[github] github release") == ("github", "github release")

    # Fallback/backward compatibility cases
    assert parse_hint("pip install extract_msg") == ("pip", "extract_msg")
    assert parse_hint("libimage-exiftool-perl") == ("apt|rpm|apk", "libimage-exiftool-perl")
    assert parse_hint("build from source") == ("build", "build from source")
    assert parse_hint("github release") == ("github", "github release")
    assert parse_hint("random package instruction") == ("other", "random package instruction")


def test_fix_hints():
    from canary_scan.lib.deps import DepStatus, fix_hints

    status = {
        "missing_required": [
            DepStatus(
                name="exiftool",
                tier="required",
                install_hint="[apt|rpm|apk] libimage-exiftool-perl",
                binary="exiftool",
                found=False,
                purpose="Metadata extraction",
            ),
        ],
        "missing_optional": [
            DepStatus(
                name="peepdf",
                tier="optional",
                install_hint="[pip] peepdf",
                binary="peepdf",
                found=False,
                purpose="Deep PDF analysis",
            ),
        ],
    }

    res = fix_hints(status)
    expected = "sudo apt install libimage-exiftool-perl\npip install peepdf"
    assert res == expected


def test_format_hint_rich():
    from canary_scan.lib.deps import format_hint_rich

    assert format_hint_rich("[apt|rpm|apk] qpdf") == "[bold white]qpdf[/bold white] [cyan]\\[apt|rpm|apk][/cyan]"
    assert format_hint_rich("[pip] peepdf") == "[bold white]peepdf[/bold white] [yellow]\\[pip][/yellow]"
    assert format_hint_rich("unsupported text") == "unsupported text"


def test_resolve_install_hint():
    from unittest.mock import patch

    from canary_scan.lib.deps import resolve_install_hint

    # Test resolving for apt
    with patch("canary_scan.lib.deps.get_local_manager", return_value=("apt", "apt")):
        assert resolve_install_hint("[apt|rpm|apk] libimage-exiftool-perl") == "[apt] libimage-exiftool-perl"
        assert resolve_install_hint("[apt|rpm|apk] python3-mutagen") == "[apt] python3-mutagen"
        assert resolve_install_hint("[pip] peepdf") == "[pip] peepdf"

    # Test resolving for rpm
    with patch("canary_scan.lib.deps.get_local_manager", return_value=("dnf", "rpm")):
        assert resolve_install_hint("[apt|rpm|apk] libimage-exiftool-perl") == "[rpm] perl-Image-ExifTool"
        assert resolve_install_hint("[apt|rpm|apk] python3-mutagen") == "[rpm] python3-mutagen"

    # Test resolving for apk
    with patch("canary_scan.lib.deps.get_local_manager", return_value=("apk", "apk")):
        assert resolve_install_hint("[apt|rpm|apk] libimage-exiftool-perl") == "[apk] perl-image-exiftool"
        assert resolve_install_hint("[apt|rpm|apk] python3-mutagen") == "[apk] py3-mutagen"
        assert resolve_install_hint("[apt|rpm|apk] unrar") == "[build] build from source"
