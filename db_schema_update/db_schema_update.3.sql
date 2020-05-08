ALTER TABLE `meta` ADD CONSTRAINT `DF_schema_version` DEFAULT 0 FOR `schema_version`
#---
ALTER TABLE `meta` ADD CONSTRAINT `DF_Lock` DEFAULT 'X' FOR `Lock`
