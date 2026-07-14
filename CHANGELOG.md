# Changelog

### Added
- `-taskargs` CLI flag and an `args` parameter on `GPOImmTask()`, allowing command-line arguments to be passed to the immediate scheduled task's `Exec` action via a new `<Arguments>` element.


### Fixed
- `GPOCopyFile()` and `GPOImmTask()` now explicitly create the `Preferences` directory (in addition to `Preferences\Files` / `Preferences\ScheduledTasks`) before writing XML, fixing failures on GPOs that don't already have a `Preferences` folder on SYSVOL.
- `GPOCopyFile()`'s directory creation no longer depends on whether `Files.xml` already exists — it now always runs instead of being skipped when the `else` branch isn't taken.
- `GPOCopyFile()`, `GPOService()`, and `GPOImmTask()` now guard against `extractInfo()` returning an empty `info`, defaulting to `[['Core GPO Engine']]` to prevent a crash on GPOs with no existing Group Policy preference extensions.
