CREATE TABLE IF NOT EXISTS `job`(
	`id` int NOT NULL AUTO_INCREMENT,
	`user` varchar(50) NOT NULL,
	`type` varchar(50) NOT NULL,
	`name` varchar(128) NOT NULL,
	`uuid` text NOT NULL,
	`status` text NOT NULL,
	`time_start` datetime DEFAULT 0,
	`time_complete` datetime DEFAULT 0,
	`apitoken` char(32) NOT NULL,
	`spec` MEDIUMTEXT NOT NULL,
	`msg` MEDIUMTEXT NOT NULL,
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)
#---
CREATE TABLE IF NOT EXISTS `session`(
	`id` int NOT NULL AUTO_INCREMENT,
	`username` varchar(50) NOT NULL,
	`last_login` datetime DEFAULT 0,
	`token_value` text NOT NULL,
	`password` text,
	KEY (`id`),
	PRIMARY KEY (`username`),
	UNIQUE KEY `username` (`username`)
)
#---
CREATE TABLE IF NOT EXISTS `role`(
	`id` int NOT NULL AUTO_INCREMENT,
	`username` varchar(50) NOT NULL,
	`role_name` text NOT NULL,
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)
#---
CREATE TABLE IF NOT EXISTS `query`(
	`id` int NOT NULL AUTO_INCREMENT,
	`job_id` int NOT NULL,
	`query` MEDIUMTEXT NOT NULL,
	`files` MEDIUMTEXT NOT NULL,
	`sizes` MEDIUMTEXT NOT NULL,
	`data` MEDIUMTEXT NOT NULL,
	PRIMARY KEY (`id`), UNIQUE KEY `id` (`id`)
)
#---
CREATE TABLE IF NOT EXISTS `meta`(
	`Lock` char(1) NOT NULL DEFAULT 'X',
	`schema_version` int NOT NULL DEFAULT 0,
	constraint PK_meta PRIMARY KEY (`Lock`),
	constraint CK_meta_Locked CHECK (`Lock`='X')
)
