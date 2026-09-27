-- +goose Up
-- package_team_id: an exclusion naming the Developer ID team that signed an installer PACKAGE, for suspicious_exec's installer
-- script chains (issue #1161). PackageKit runs every package's scripts under Apple's package_script_service, so the chain names
-- Apple and never the vendor, and every other match type the rule reads lands on Apple's installer and trusts every package. The
-- agent attaches the package's signature to the script's exec; this is what lets an operator trust one vendor's installers.
--
-- Appended to the ENUM, which MySQL 8 applies as a metadata change with no table rebuild.

-- +goose StatementBegin
ALTER TABLE detection_exclusions
	MODIFY COLUMN match_type ENUM('path_glob','parent_path_glob','team_id','signing_id','cdhash','sha256','command_substring','domain',
		'package_team_id') NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE FROM detection_exclusions WHERE match_type = 'package_team_id';
ALTER TABLE detection_exclusions
	MODIFY COLUMN match_type ENUM('path_glob','parent_path_glob','team_id','signing_id','cdhash','sha256','command_substring','domain')
		NOT NULL;
-- +goose StatementEnd
