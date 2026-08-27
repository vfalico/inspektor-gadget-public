import pathlib
import unittest


SKILL = pathlib.Path(__file__).parents[1] / "SKILL.md"


def folded_description(text: str) -> str:
    lines = text.splitlines()
    start = lines.index("description: >-") + 1
    description = []
    for line in lines[start:]:
        if not line.startswith("  "):
            break
        description.append(line.strip())
    return " ".join(description)


class SkillMetadataTest(unittest.TestCase):
    def test_description_fits_copilot_skill_limit(self):
        description = folded_description(SKILL.read_text(encoding="utf-8"))
        self.assertTrue(description)
        self.assertLessEqual(len(description), 1024)


if __name__ == "__main__":
    unittest.main()
