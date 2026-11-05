// Conventional Commits, enforced on pull requests and by the lefthook
// commit-msg hook. Types match the release-please changelog sections.
export default {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "type-enum": [
      2,
      "always",
      [
        "feat",
        "fix",
        "perf",
        "security",
        "deps",
        "docs",
        "refactor",
        "test",
        "build",
        "ci",
        "chore",
        "revert",
        "style",
      ],
    ],
    "body-max-line-length": [0],
  },
};
