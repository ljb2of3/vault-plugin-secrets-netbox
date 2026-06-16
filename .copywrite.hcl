schema_version = 1

project {
  license          = "MPL-2.0"
  copyright_holder = "Landy Bible <landy@ljb2of3.net>"
  copyright_year   = 2026

  # Paths copywrite should not add headers to. Globs are relative to repo root.
  header_ignore = [
    ".golangci.yml",
    ".goreleaser.yml"
  ]
}
